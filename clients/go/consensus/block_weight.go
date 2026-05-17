package consensus

func txWeightAndStats(tx *Tx) (uint64, uint64, uint64, error) {
	return txWeightComponents(tx, func(w WitnessItem) (uint64, error) {
		switch w.SuiteID {
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
