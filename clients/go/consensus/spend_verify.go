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

// verifyMLDSAKeyAndSig verifies an ML-DSA-87 witness item's key binding and
// cryptographic signature. The caller must validate witness item lengths and
// suite ID before calling this function.
func verifyMLDSAKeyAndSig(w WitnessItem, expectedKeyID [32]byte, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, context string) error {
	if sha3_256(w.Pubkey) != expectedKeyID {
		return txerr(TX_ERR_SIG_INVALID, context+" key binding mismatch")
	}
	cryptoSig, sighashType, err := extractCryptoSigAndSighash(w)
	if err != nil {
		return err
	}
	digest, err := SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, sighashType)
	if err != nil {
		return err
	}
	ok, err := verifySig(w.SuiteID, w.Pubkey, cryptoSig, digest)
	if err != nil {
		return err
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, context+" signature invalid")
	}
	return nil
}

func validateP2PKSpend(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64) error {
	if w.SuiteID != SUITE_ID_ML_DSA_87 {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite invalid")
	}
	_ = blockHeight
	if len(w.Pubkey) != ML_DSA_87_PUBKEY_BYTES || len(w.Signature) != ML_DSA_87_SIG_BYTES+1 {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical ML-DSA witness item lengths")
	}
	if len(entry.CovenantData) != MAX_P2PK_COVENANT_DATA || entry.CovenantData[0] != w.SuiteID {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_P2PK covenant_data invalid")
	}
	var keyID [32]byte
	copy(keyID[:], entry.CovenantData[1:33])
	return verifyMLDSAKeyAndSig(w, keyID, tx, inputIndex, inputValue, chainID, "CORE_P2PK")
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
	if len(ws) != len(keys) {
		return txerr(TX_ERR_PARSE, "witness slot assignment mismatch")
	}
	valid := 0
	for i := range keys {
		w := ws[i]
		switch w.SuiteID {
		case SUITE_ID_SENTINEL:
			if len(w.Pubkey) != 0 || len(w.Signature) != 0 {
				return txerr(TX_ERR_PARSE, "SENTINEL witness must be keyless")
			}
			continue
		case SUITE_ID_ML_DSA_87:
			_ = blockHeight
			if len(w.Pubkey) != ML_DSA_87_PUBKEY_BYTES || len(w.Signature) != ML_DSA_87_SIG_BYTES+1 {
				return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical ML-DSA witness item lengths")
			}
			if err := verifyMLDSAKeyAndSig(w, keys[i], tx, inputIndex, inputValue, chainID, context); err != nil {
				return err
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
