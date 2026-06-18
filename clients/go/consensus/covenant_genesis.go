package consensus

// ValidateTxCovenantsGenesis checks that every output's covenant is well-formed
// at creation time. The rotation parameter controls which signature suites are
// valid for native covenant creation at the given block height. Pass nil for
// the default pre-rotation behavior ({ML-DSA-87} only).
func ValidateTxCovenantsGenesis(tx *Tx, blockHeight uint64, rotation RotationProvider) error {
	if tx == nil {
		return txerr(TX_ERR_PARSE, "nil tx")
	}
	if rotation == nil {
		rotation = DefaultRotationProvider{}
	}
	simplicityDeployment := simplicityDeploymentFromRotation(rotation)

	for _, out := range tx.Outputs {
		if err := validateTxOutputCovenantGenesis(tx.TxKind, out, blockHeight, rotation, simplicityDeployment); err != nil {
			return err
		}
	}
	return nil
}

func validateTxOutputCovenantGenesis(txKind byte, out TxOutput, blockHeight uint64, rotation RotationProvider, simplicityDeployment SimplicityDeploymentProvider) error {
	switch out.CovenantType {
	case COV_TYPE_P2PK:
		return validateP2PKGenesisOutput(out, blockHeight, rotation)
	case COV_TYPE_ANCHOR:
		return validateAnchorGenesisOutput(out)
	case COV_TYPE_DA_COMMIT:
		return validateDACommitGenesisOutput(txKind, out)
	case COV_TYPE_VAULT, COV_TYPE_MULTISIG, COV_TYPE_HTLC, COV_TYPE_CORE_EXT, COV_TYPE_CORE_STEALTH:
		return validateParsedValueGenesisOutput(out)
	case COV_TYPE_CORE_SIMPLICITY:
		if err := validateCoreSimplicityDeploymentActive(blockHeight, simplicityDeployment); err != nil {
			return err
		}
		_, _, err := parseCoreSimplicityCovenantData(out.Value, out.CovenantData)
		return err
	case COV_TYPE_RESERVED_FUTURE:
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "reserved covenant_type")
	default:
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "unknown covenant_type")
	}
}

func validateP2PKGenesisOutput(out TxOutput, blockHeight uint64, rotation RotationProvider) error {
	if out.Value == 0 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_P2PK value must be > 0")
	}
	if len(out.CovenantData) != MAX_P2PK_COVENANT_DATA {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_P2PK covenant_data length")
	}
	suiteID := out.CovenantData[0]
	if !rotation.NativeCreateSuites(blockHeight).Contains(suiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite not in native create set")
	}
	return nil
}

func validateAnchorGenesisOutput(out TxOutput) error {
	if out.Value != 0 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_ANCHOR value must be 0")
	}
	covLen := len(out.CovenantData)
	if covLen == 0 || covLen > MAX_ANCHOR_PAYLOAD_SIZE {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_ANCHOR covenant_data length")
	}
	return nil
}

func validateParsedValueGenesisOutput(out TxOutput) error {
	switch out.CovenantType {
	case COV_TYPE_VAULT:
		return validateVaultGenesisOutput(out)
	case COV_TYPE_MULTISIG:
		return validateMultisigGenesisOutput(out)
	case COV_TYPE_HTLC:
		return validateHTLCGenesisOutput(out)
	case COV_TYPE_CORE_EXT:
		return validateCoreExtGenesisOutput(out)
	case COV_TYPE_CORE_STEALTH:
		return validateCoreStealthGenesisOutput(out)
	default:
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "unknown covenant_type")
	}
}

func validateVaultGenesisOutput(out TxOutput) error {
	if out.Value == 0 {
		return txerr(TX_ERR_VAULT_PARAMS_INVALID, "CORE_VAULT value must be > 0")
	}
	_, err := ParseVaultCovenantData(out.CovenantData)
	return err
}

func validateMultisigGenesisOutput(out TxOutput) error {
	if out.Value == 0 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_MULTISIG value must be > 0")
	}
	_, err := ParseMultisigCovenantData(out.CovenantData)
	return err
}

func validateHTLCGenesisOutput(out TxOutput) error {
	if out.Value == 0 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_HTLC value must be > 0")
	}
	_, err := ParseHTLCCovenantData(out.CovenantData)
	return err
}

func validateCoreExtGenesisOutput(out TxOutput) error {
	if out.Value == 0 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT value must be > 0")
	}
	_, err := ParseCoreExtCovenantData(out.CovenantData)
	return err
}

func validateCoreStealthGenesisOutput(out TxOutput) error {
	if out.Value == 0 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_STEALTH value must be > 0")
	}
	_, err := ParseStealthCovenantData(out.CovenantData)
	return err
}

func validateDACommitGenesisOutput(txKind byte, out TxOutput) error {
	if txKind != 0x01 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_DA_COMMIT allowed only in tx_kind=0x01")
	}
	if out.Value != 0 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_DA_COMMIT value must be 0")
	}
	if len(out.CovenantData) != 32 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "invalid CORE_DA_COMMIT covenant_data length")
	}
	return nil
}
