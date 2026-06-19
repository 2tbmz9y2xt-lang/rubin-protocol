package consensus

// txWeightComponents computes the common weight components shared by both
// legacy and registry-aware weight calculations: baseSize, witnessSize,
// anchorBytes, daBytes. It also iterates witness items and calls sigCostFn
// for each non-sentinel witness to accumulate sig verification cost.
//
// sigCostFn receives a WitnessItem and returns (cost uint64, err error).
// For sentinel items (SuiteID == SUITE_ID_SENTINEL) the callback is skipped.
func txWeightComponents(tx *Tx, sigCostFn func(WitnessItem) (uint64, error)) (uint64, uint64, uint64, error) {
	if tx == nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "nil tx")
	}

	baseSize, anchorBytes, err := computeTxBaseSize(tx)
	if err != nil {
		return 0, 0, 0, err
	}

	witnessSize, sigCost, err := computeTxWitness(tx, sigCostFn)
	if err != nil {
		return 0, 0, 0, err
	}

	daSize, daBytes := computeTxDASize(tx)

	baseWeight, err := mulU64(WITNESS_DISCOUNT_DIVISOR, baseSize)
	if err != nil {
		return 0, 0, 0, err
	}
	weight, err := addU64(baseWeight, witnessSize)
	if err != nil {
		return 0, 0, 0, err
	}
	weight, err = addU64(weight, daSize)
	if err != nil {
		return 0, 0, 0, err
	}
	weight, err = addU64(weight, sigCost)
	if err != nil {
		return 0, 0, 0, err
	}

	return weight, daBytes, anchorBytes, nil
}

// computeTxBaseSize calculates the base serialization size for a transaction:
// version + tx_kind + nonce + inputs (with script_sig) + outputs (with
// covenant_data) + locktime + da_core fields. Returns base size and accumulated
// anchor bytes from anchor/da_commit covenant types.
func computeTxBaseSize(tx *Tx) (uint64, uint64, error) {
	baseSize := uint64(4 + 1 + 8)
	var err error
	baseSize, err = addU64(baseSize, compactSizeLen(uint64(len(tx.Inputs))))
	if err != nil {
		return 0, 0, txerr(TX_ERR_PARSE, "tx base size overflow")
	}
	baseSize, err = addInputSizes(baseSize, tx.Inputs)
	if err != nil {
		return 0, 0, err
	}
	baseSize, err = addU64(baseSize, compactSizeLen(uint64(len(tx.Outputs))))
	if err != nil {
		return 0, 0, txerr(TX_ERR_PARSE, "tx base size overflow")
	}
	baseSize, anchorBytes, err := addOutputSizes(baseSize, tx.Outputs)
	if err != nil {
		return 0, 0, err
	}
	baseSize, err = addU64(baseSize, 4)
	if err != nil {
		return 0, 0, txerr(TX_ERR_PARSE, "tx base size overflow")
	}
	daCoreBytes, err := daCoreFieldsBytes(tx)
	if err != nil {
		return 0, 0, err
	}
	baseSize, err = addU64(baseSize, uint64(len(daCoreBytes)))
	if err != nil {
		return 0, 0, err
	}
	return baseSize, anchorBytes, nil
}

func addInputSizes(baseSize uint64, inputs []TxInput) (uint64, error) {
	var err error
	for _, in := range inputs {
		baseSize, err = addU64(baseSize, 32+4)
		if err != nil {
			return 0, err
		}
		baseSize, err = addU64(baseSize, compactSizeLen(uint64(len(in.ScriptSig))))
		if err != nil {
			return 0, err
		}
		baseSize, err = addU64(baseSize, uint64(len(in.ScriptSig)))
		if err != nil {
			return 0, err
		}
		baseSize, err = addU64(baseSize, 4)
		if err != nil {
			return 0, err
		}
	}
	return baseSize, nil
}

func addOutputSizes(baseSize uint64, outputs []TxOutput) (uint64, uint64, error) {
	var err error
	var anchorBytes uint64
	for _, out := range outputs {
		baseSize, err = addU64(baseSize, 8+2)
		if err != nil {
			return 0, 0, err
		}
		covLen := uint64(len(out.CovenantData))
		baseSize, err = addU64(baseSize, compactSizeLen(covLen))
		if err != nil {
			return 0, 0, err
		}
		baseSize, err = addU64(baseSize, covLen)
		if err != nil {
			return 0, 0, err
		}
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			anchorBytes, err = addU64(anchorBytes, covLen)
			if err != nil {
				return 0, 0, err
			}
		}
	}
	return baseSize, anchorBytes, nil
}

// computeTxWitness iterates witness items to derive witness serialization size
// and accumulated sig verification cost via sigCostFn.
func computeTxWitness(tx *Tx, sigCostFn func(WitnessItem) (uint64, error)) (uint64, uint64, error) {
	witnessSize := compactSizeLen(uint64(len(tx.Witness)))
	var sigCost uint64
	var err error
	for _, w := range tx.Witness {
		witnessSize, sigCost, err = addWitnessItemSize(witnessSize, sigCost, w, sigCostFn)
		if err != nil {
			return 0, 0, err
		}
	}
	return witnessSize, sigCost, nil
}

func addWitnessItemSize(witnessSize, sigCost uint64, w WitnessItem, sigCostFn func(WitnessItem) (uint64, error)) (uint64, uint64, error) {
	var err error
	witnessSize, err = addWitnessItemSerialSize(witnessSize, w)
	if err != nil {
		return 0, 0, err
	}
	if w.SuiteID == SUITE_ID_SENTINEL {
		return witnessSize, sigCost, nil
	}
	cost, costErr := sigCostFn(w)
	if costErr != nil {
		return 0, 0, costErr
	}
	sigCost, err = addU64(sigCost, cost)
	if err != nil {
		return 0, 0, err
	}
	return witnessSize, sigCost, nil
}

func addWitnessItemSerialSize(witnessSize uint64, w WitnessItem) (uint64, error) {
	var err error
	witnessSize, err = addU64(witnessSize, 1)
	if err != nil {
		return 0, err
	}
	witnessSize, err = addU64(witnessSize, compactSizeLen(uint64(len(w.Pubkey))))
	if err != nil {
		return 0, err
	}
	witnessSize, err = addU64(witnessSize, uint64(len(w.Pubkey)))
	if err != nil {
		return 0, err
	}
	witnessSize, err = addU64(witnessSize, compactSizeLen(uint64(len(w.Signature))))
	if err != nil {
		return 0, err
	}
	witnessSize, err = addU64(witnessSize, uint64(len(w.Signature)))
	if err != nil {
		return 0, err
	}
	return witnessSize, nil
}

// computeTxDASize returns the DA payload serialization size (compact_size
// prefix + raw bytes) and effective DA byte count (nonzero only for non-
// coinbase transactions).
func computeTxDASize(tx *Tx) (uint64, uint64) {
	daLen := uint64(len(tx.DaPayload))
	daSize := compactSizeLen(daLen) + daLen
	daBytes := uint64(0)
	if tx.TxKind != 0x00 {
		daBytes = daLen
	}
	return daSize, daBytes
}

// txWeightAndStats computes legacy weight with hardcoded per-suite costs.
func txWeightAndStats(tx *Tx) (uint64, uint64, uint64, error) {
	return txWeightComponents(tx, func(w WitnessItem) (uint64, error) {
		switch w.SuiteID {
		case SUITE_ID_SIMPLICITY_ENVELOPE:
			return SIMPLICITY_BASE_VERIFY_COST, nil
		case SUITE_ID_ML_DSA_87:
			if len(w.Pubkey) == ML_DSA_87_PUBKEY_BYTES && len(w.Signature) == ML_DSA_87_SIG_BYTES+1 {
				return VERIFY_COST_ML_DSA_87, nil
			}
			// Malformed native witness: zero sig_cost because witness bytes still
			// contribute via wit_size and validation rejects on cheap length checks
			// without invoking expensive crypto verification.
			return 0, nil
		default:
			return VERIFY_COST_UNKNOWN_SUITE, nil
		}
	})
}

func compactSizeLen(n uint64) uint64 {
	switch {
	case n < 0xfd:
		return 1
	case n <= 0xffff:
		return 3
	case n <= 0xffff_ffff:
		return 5
	default:
		return 9
	}
}

func addU64(a uint64, b uint64) (uint64, error) {
	if a > ^uint64(0)-b {
		return 0, txerr(TX_ERR_PARSE, "u64 overflow")
	}
	return a + b, nil
}

func mulU64(a uint64, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > ^uint64(0)/b {
		return 0, txerr(TX_ERR_PARSE, "u64 overflow")
	}
	return a * b, nil
}

// TxWeightAndStats exposes consensus weight accounting for conformance and formal tooling.
// It is a pure function of a parsed Tx and does not consult chainstate.
func TxWeightAndStats(tx *Tx) (uint64, uint64, uint64, error) {
	return txWeightAndStats(tx)
}

// TxWeightAndStatsAtHeight computes weight using per-suite verify costs from
// the registry and height-aware native spend suites from the rotation provider.
// This is the consensus-path entry point; the legacy TxWeightAndStats uses
// hardcoded costs as a conservative upper bound.
func TxWeightAndStatsAtHeight(tx *Tx, height uint64, rotation RotationProvider, registry *SuiteRegistry) (uint64, uint64, uint64, error) {
	return txWeightAndStatsWithRegistry(tx, height, rotation, registry)
}

// txWeightAndStatsWithRegistry is the suite-aware weight calculation.
// It delegates to txWeightComponents with a registry-aware sig cost function.
func txWeightAndStatsWithRegistry(tx *Tx, height uint64, rotation RotationProvider, registry *SuiteRegistry) (uint64, uint64, uint64, error) {
	if tx == nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "nil tx")
	}
	if rotation == nil || registry == nil {
		return txWeightAndStats(tx)
	}

	nativeSpend := rotation.NativeSpendSuites(height)

	return txWeightComponents(tx, func(w WitnessItem) (uint64, error) {
		if w.SuiteID == SUITE_ID_SIMPLICITY_ENVELOPE {
			return SIMPLICITY_BASE_VERIFY_COST, nil
		}
		if nativeSpend.Contains(w.SuiteID) {
			if params, ok := registry.Lookup(w.SuiteID); ok {
				// Native registered suite: use registry cost if lengths match,
				// else zero (matches legacy — malformed native witness items
				// still pay through wit_size and fail on cheap length checks,
				// so they are not charged as unknown suites).
				if len(w.Pubkey) == params.PubkeyLen && len(w.Signature) == params.SigLen+1 {
					return params.VerifyCost, nil
				}
				return 0, nil
			}
			// In native spend set but not registered — treat as unknown.
			return VERIFY_COST_UNKNOWN_SUITE, nil
		}
		// Not in native spend set — unknown suite floor.
		return VERIFY_COST_UNKNOWN_SUITE, nil
	})
}
