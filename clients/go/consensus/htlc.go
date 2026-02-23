package consensus

import "encoding/binary"

type HTLCCovenant struct {
	Hash        [32]byte
	LockMode    uint8
	LockValue   uint64
	ClaimKeyID  [32]byte
	RefundKeyID [32]byte
}

func ParseHTLCCovenantData(covData []byte) (*HTLCCovenant, error) {
	if covData == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "nil CORE_HTLC covenant_data")
	}
	if len(covData) != MAX_HTLC_COVENANT_DATA {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_HTLC covenant_data length mismatch")
	}

	var c HTLCCovenant
	copy(c.Hash[:], covData[0:32])
	c.LockMode = covData[32]
	c.LockValue = binary.LittleEndian.Uint64(covData[33:41])
	copy(c.ClaimKeyID[:], covData[41:73])
	copy(c.RefundKeyID[:], covData[73:105])

	if c.LockMode != LOCK_MODE_HEIGHT && c.LockMode != LOCK_MODE_TIMESTAMP {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_HTLC lock_mode invalid")
	}
	if c.ClaimKeyID == c.RefundKeyID {
		return nil, txerr(TX_ERR_PARSE, "CORE_HTLC claim/refund key_id must differ")
	}

	return &c, nil
}

func ValidateHTLCSpend(
	entry UtxoEntry,
	pathItem WitnessItem,
	sigItem WitnessItem,
	blockHeight uint64,
	blockTimestamp uint64,
) error {
	c, err := ParseHTLCCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}

	var expectedKeyID [32]byte
	switch pathItem.SuiteID {
	case LOCK_MODE_HEIGHT: // claim path selector = 0x00
		if len(pathItem.Pubkey) != 32 {
			return txerr(TX_ERR_PARSE, "CORE_HTLC claim path key_id length invalid")
		}
		var pathKeyID [32]byte
		copy(pathKeyID[:], pathItem.Pubkey)
		if pathKeyID != c.ClaimKeyID {
			return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC claim key_id mismatch")
		}
		if len(pathItem.Signature) < 2 {
			return txerr(TX_ERR_PARSE, "CORE_HTLC claim payload too short")
		}
		preLen := int(binary.LittleEndian.Uint16(pathItem.Signature[:2]))
		if preLen > MAX_HTLC_PREIMAGE_BYTES {
			return txerr(TX_ERR_PARSE, "CORE_HTLC preimage length overflow")
		}
		if len(pathItem.Signature) != 2+preLen {
			return txerr(TX_ERR_PARSE, "CORE_HTLC claim payload length mismatch")
		}
		preimage := pathItem.Signature[2:]
		if sha3_256(preimage) != c.Hash {
			return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC claim preimage hash mismatch")
		}
		expectedKeyID = c.ClaimKeyID

	case LOCK_MODE_TIMESTAMP: // refund path selector = 0x01
		if len(pathItem.Pubkey) != 32 {
			return txerr(TX_ERR_PARSE, "CORE_HTLC refund path key_id length invalid")
		}
		if len(pathItem.Signature) != 0 {
			return txerr(TX_ERR_PARSE, "CORE_HTLC refund path payload must be empty")
		}
		var pathKeyID [32]byte
		copy(pathKeyID[:], pathItem.Pubkey)
		if pathKeyID != c.RefundKeyID {
			return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC refund key_id mismatch")
		}
		if c.LockMode == LOCK_MODE_HEIGHT {
			if blockHeight < c.LockValue {
				return txerr(TX_ERR_TIMELOCK_NOT_MET, "CORE_HTLC height lock not met")
			}
		} else if blockTimestamp < c.LockValue {
			return txerr(TX_ERR_TIMELOCK_NOT_MET, "CORE_HTLC timestamp lock not met")
		}
		expectedKeyID = c.RefundKeyID

	default:
		return txerr(TX_ERR_PARSE, "CORE_HTLC unknown spend path")
	}

	switch sigItem.SuiteID {
	case SUITE_ID_ML_DSA_87:
		if len(sigItem.Pubkey) != ML_DSA_87_PUBKEY_BYTES || len(sigItem.Signature) != ML_DSA_87_SIG_BYTES {
			return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical ML-DSA witness item lengths")
		}
	case SUITE_ID_SLH_DSA_SHAKE_256F:
		if blockHeight < SLH_DSA_ACTIVATION_HEIGHT {
			return txerr(TX_ERR_SIG_ALG_INVALID, "SLH-DSA suite inactive at this height")
		}
		if len(sigItem.Pubkey) != SLH_DSA_SHAKE_256F_PUBKEY_BYTES || len(sigItem.Signature) == 0 || len(sigItem.Signature) > MAX_SLH_DSA_SIG_BYTES {
			return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical SLH-DSA witness item lengths")
		}
	default:
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_HTLC sig_item suite invalid")
	}

	if sha3_256(sigItem.Pubkey) != expectedKeyID {
		return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC signature key binding mismatch")
	}

	// Basic profile currently checks structural and binding rules only.
	// Full cryptographic signature verification is validated in higher-level conformance.
	return nil
}
