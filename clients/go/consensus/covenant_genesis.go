package consensus

func ValidateTxCovenantsGenesis(tx *Tx, blockHeight uint64) error {
	if tx == nil {
		return txerr(TX_ERR_PARSE, "nil tx")
	}

	for _, out := range tx.Outputs {
		switch out.CovenantType {
		case COV_TYPE_P2PK:
			if out.Value == 0 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_P2PK value must be > 0")
			}
			if len(out.CovenantData) != MAX_P2PK_COVENANT_DATA {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_P2PK covenant_data length")
			}
			suiteID := out.CovenantData[0]
			if suiteID != SUITE_ID_ML_DSA_87 && suiteID != SUITE_ID_SLH_DSA_SHAKE_256F {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_P2PK suite_id")
			}
			if suiteID == SUITE_ID_SLH_DSA_SHAKE_256F && blockHeight < SLH_DSA_ACTIVATION_HEIGHT {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_P2PK SLH-DSA suite inactive at this height")
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
			if out.Value == 0 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_VAULT value must be > 0")
			}
			if _, err := ParseVaultCovenantData(out.CovenantData); err != nil {
				return err
			}
		case COV_TYPE_MULTISIG:
			if out.Value == 0 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_MULTISIG value must be > 0")
			}
			if _, err := ParseMultisigCovenantData(out.CovenantData); err != nil {
				return err
			}
		case COV_TYPE_HTLC:
			if out.Value == 0 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_HTLC value must be > 0")
			}
			if _, err := ParseHTLCCovenantData(out.CovenantData); err != nil {
				return err
			}

		case COV_TYPE_DA_COMMIT:
			if tx.TxKind != 0x01 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_DA_COMMIT allowed only in tx_kind=0x01")
			}
			if out.Value != 0 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_DA_COMMIT value must be 0")
			}
			if len(out.CovenantData) != 32 {
				return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_DA_COMMIT covenant_data length")
			}
		case COV_TYPE_RESERVED_FUTURE:
			return txerr(TX_ERR_COVENANT_TYPE_INVALID, "reserved covenant_type")

		default:
			return txerr(TX_ERR_COVENANT_TYPE_INVALID, "unknown covenant_type")
		}
	}

	return nil
}
