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

	// Same-program_cmr CORE_SIMPLICITY outputs are capped at
	// SIMPLICITY_MAX_GROUP_OUTPUTS on this live creation/apply path, mirroring the
	// same-cmr input group cap. The count is over tx.Outputs in wire order (no map
	// iteration feeds the decision), and the cap does not depend on spending a
	// CORE_SIMPLICITY input or on BuildSimplicityTxContext being constructed.
	var simplicityOutputGroups map[[32]byte]int
	for _, out := range tx.Outputs {
		programCMR, isCoreSimplicity, err := validateTxOutputCovenantGenesis(tx.TxKind, out, blockHeight, rotation, simplicityDeployment)
		if err != nil {
			return err
		}
		if !isCoreSimplicity {
			continue
		}
		if simplicityOutputGroups == nil {
			simplicityOutputGroups = make(map[[32]byte]int)
		}
		simplicityOutputGroups[programCMR]++
		if simplicityOutputGroups[programCMR] > SIMPLICITY_MAX_GROUP_OUTPUTS {
			return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY same-cmr output group exceeds limit")
		}
	}
	return nil
}

// validateTxOutputCovenantGenesis validates one output's covenant at creation.
// For a well-formed CORE_SIMPLICITY output it returns the parsed program_cmr and
// true so the caller can enforce the same-cmr output group cap on the live path;
// every other covenant type returns the zero cmr and false.
func validateTxOutputCovenantGenesis(txKind byte, out TxOutput, blockHeight uint64, rotation RotationProvider, simplicityDeployment SimplicityDeploymentProvider) ([32]byte, bool, error) {
	switch out.CovenantType {
	case COV_TYPE_P2PK:
		return [32]byte{}, false, validateP2PKGenesisOutput(out, blockHeight, rotation)
	case COV_TYPE_ANCHOR:
		return [32]byte{}, false, validateAnchorGenesisOutput(out)
	case COV_TYPE_DA_COMMIT:
		return [32]byte{}, false, validateDACommitGenesisOutput(txKind, out)
	case COV_TYPE_VAULT, COV_TYPE_MULTISIG, COV_TYPE_HTLC, COV_TYPE_CORE_STEALTH:
		return [32]byte{}, false, validateParsedValueGenesisOutput(out)
	case COV_TYPE_CORE_SIMPLICITY:
		return validateCoreSimplicityGenesisOutput(out, blockHeight, simplicityDeployment)
	case COV_TYPE_RESERVED_FUTURE:
		return [32]byte{}, false, txerr(TX_ERR_COVENANT_TYPE_INVALID, "reserved covenant_type")
	default:
		return [32]byte{}, false, txerr(TX_ERR_COVENANT_TYPE_INVALID, "unknown covenant_type")
	}
}

// validateCoreSimplicityGenesisOutput validates a CORE_SIMPLICITY creation output
// and, on success, returns its program_cmr and true so the caller can enforce the
// same-cmr output group cap.
func validateCoreSimplicityGenesisOutput(out TxOutput, blockHeight uint64, simplicityDeployment SimplicityDeploymentProvider) ([32]byte, bool, error) {
	if err := validateCoreSimplicityDeploymentActive(blockHeight, simplicityDeployment); err != nil {
		return [32]byte{}, false, err
	}
	programCMR, _, err := parseCoreSimplicityCovenantData(out.Value, out.CovenantData)
	if err != nil {
		return [32]byte{}, false, err
	}
	return programCMR, true, nil
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
