package consensus

func ValidateTxCovenantsGenesis(tx *Tx) error {
	if tx == nil {
		return txerr(TX_ERR_PARSE, "nil tx")
	}

	for _, out := range tx.Outputs {
		switch out.CovenantType {
		case COV_TYPE_P2PK:
			if len(out.CovenantData) != MAX_P2PK_COVENANT_DATA {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_P2PK covenant_data length")
			}
			if out.CovenantData[0] != SUITE_ID_ML_DSA_87 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_P2PK suite_id")
			}

		case COV_TYPE_TIMELOCK:
			if len(out.CovenantData) != MAX_TIMELOCK_COVENANT_DATA {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_TIMELOCK covenant_data length")
			}
			lockMode := out.CovenantData[0]
			if lockMode != 0x00 && lockMode != 0x01 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_TIMELOCK lock_mode")
			}

		case COV_TYPE_ANCHOR:
			if out.Value != 0 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_ANCHOR value must be 0")
			}
			covLen := len(out.CovenantData)
			if covLen == 0 || covLen > MAX_ANCHOR_PAYLOAD_SIZE {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_ANCHOR covenant_data length")
			}

		case COV_TYPE_VAULT:
			// Q-V01 pending: until vault semantics are ratified, reject 0x0101.
			return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT semantics pending")

		case COV_TYPE_RESERVED_FUTURE, COV_TYPE_HTLC, COV_TYPE_DA_COMMIT:
			return txerr(TX_ERR_COVENANT_TYPE_INVALID, "reserved or unsupported covenant_type")

		default:
			return txerr(TX_ERR_COVENANT_TYPE_INVALID, "unknown covenant_type")
		}
	}

	return nil
}
