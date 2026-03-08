package consensus

type StealthCovenant struct {
	Ciphertext   []byte
	OneTimeKeyID [32]byte
}

func ParseStealthCovenantData(covData []byte) (*StealthCovenant, error) {
	if covData == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "nil CORE_STEALTH covenant_data")
	}
	if len(covData) != MAX_STEALTH_COVENANT_DATA {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_STEALTH covenant_data length mismatch")
	}
	if ML_KEM_1024_CT_BYTES+32 != MAX_STEALTH_COVENANT_DATA {
		return nil, txerr(TX_ERR_PARSE, "CORE_STEALTH constants mismatch")
	}
	var oneTimeKeyID [32]byte
	copy(oneTimeKeyID[:], covData[ML_KEM_1024_CT_BYTES:MAX_STEALTH_COVENANT_DATA])
	return &StealthCovenant{
		Ciphertext:   append([]byte(nil), covData[:ML_KEM_1024_CT_BYTES]...),
		OneTimeKeyID: oneTimeKeyID,
	}, nil
}

func validateCoreStealthSpend(entry UtxoEntry, w WitnessItem, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, blockHeight uint64) error {
	c, err := ParseStealthCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}

	if w.SuiteID != SUITE_ID_ML_DSA_87 {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_STEALTH suite invalid")
	}
	_ = blockHeight
	if len(w.Pubkey) != ML_DSA_87_PUBKEY_BYTES || len(w.Signature) != ML_DSA_87_SIG_BYTES+1 {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical ML-DSA witness item lengths")
	}
	return verifyMLDSAKeyAndSig(w, c.OneTimeKeyID, tx, inputIndex, inputValue, chainID, "CORE_STEALTH")
}
