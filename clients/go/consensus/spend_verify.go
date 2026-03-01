package consensus

// Q-CF-18: checkSLHCanonical validates SLH-DSA-SHAKE-256f witness-item byte lengths.
// Returns nil for non-SLH suite IDs. Must be called after the activation check.
func checkSLHCanonical(w WitnessItem) error {
	if w.SuiteID != SUITE_ID_SLH_DSA_SHAKE_256F {
		return nil
	}
	if len(w.Pubkey) != SLH_DSA_SHAKE_256F_PUBKEY_BYTES ||
		len(w.Signature) != MAX_SLH_DSA_SIG_BYTES {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical SLH-DSA witness item lengths")
	}
	return nil
}

func validateP2PKSpend(entry UtxoEntry, w WitnessItem, digest [32]byte, blockHeight uint64) error {
	if w.SuiteID != SUITE_ID_ML_DSA_87 && w.SuiteID != SUITE_ID_SLH_DSA_SHAKE_256F {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite invalid")
	}
	if w.SuiteID == SUITE_ID_SLH_DSA_SHAKE_256F && blockHeight < SLH_DSA_ACTIVATION_HEIGHT {
		return txerr(TX_ERR_SIG_ALG_INVALID, "SLH-DSA suite inactive at this height")
	}
	if err := checkSLHCanonical(w); err != nil {
		return err
	}
	if len(entry.CovenantData) != MAX_P2PK_COVENANT_DATA || entry.CovenantData[0] != w.SuiteID {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_P2PK covenant_data invalid")
	}
	var keyID [32]byte
	copy(keyID[:], entry.CovenantData[1:33])
	if sha3_256(w.Pubkey) != keyID {
		return txerr(TX_ERR_SIG_INVALID, "CORE_P2PK key binding mismatch")
	}
	ok, err := verifySig(w.SuiteID, w.Pubkey, w.Signature, digest)
	if err != nil {
		return err
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, "CORE_P2PK signature invalid")
	}
	return nil
}

func validateThresholdSigSpend(keys [][32]byte, threshold uint8, ws []WitnessItem, digest [32]byte, blockHeight uint64, context string) error {
	if len(ws) != len(keys) {
		return txerr(TX_ERR_PARSE, "witness slot assignment mismatch")
	}
	valid := 0
	for i := range keys {
		w := ws[i]
		switch w.SuiteID {
		case SUITE_ID_SENTINEL:
			continue
		case SUITE_ID_ML_DSA_87, SUITE_ID_SLH_DSA_SHAKE_256F:
			if w.SuiteID == SUITE_ID_SLH_DSA_SHAKE_256F && blockHeight < SLH_DSA_ACTIVATION_HEIGHT {
				return txerr(TX_ERR_SIG_ALG_INVALID, "SLH-DSA suite inactive at this height")
			}
			if err := checkSLHCanonical(w); err != nil {
				return err
			}
			if sha3_256(w.Pubkey) != keys[i] {
				return txerr(TX_ERR_SIG_INVALID, context+" key binding mismatch")
			}
			ok, err := verifySig(w.SuiteID, w.Pubkey, w.Signature, digest)
			if err != nil {
				return err
			}
			if !ok {
				return txerr(TX_ERR_SIG_INVALID, context+" signature invalid")
			}
			valid++
		default:
			// Unknown suites are accepted at parse stage (CANONICAL §12.2 / CV-SIG-05);
			// non-CORE_EXT spend paths must reject them deterministically here.
			return txerr(TX_ERR_SIG_ALG_INVALID, context+" suite invalid")
		}
	}
	if valid < int(threshold) {
		return txerr(TX_ERR_SIG_INVALID, context+" threshold not met")
	}
	return nil
}
