package consensus

type SimplicityDeploymentProvider interface {
	SimplicityActiveAtHeight(height uint64) (bool, error)
}

func rejectCoreSimplicitySpend() error {
	return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
}

func simplicityDeploymentFromRotation(rotation RotationProvider) SimplicityDeploymentProvider {
	provider, ok := rotation.(SimplicityDeploymentProvider)
	if !ok {
		return nil
	}
	return provider
}

func validateCoreSimplicityCovenantData(value uint64, covenantData []byte) error {
	if value == 0 {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY value must be > 0")
	}

	_, _, err := parseCoreSimplicityCovenantData(covenantData)
	return err
}

func parseCoreSimplicityCovenantData(covenantData []byte) ([32]byte, []byte, error) {
	var programCMR [32]byte
	off := 0
	cmrBytes, err := readBytes(covenantData, &off, 32)
	if err != nil {
		return programCMR, nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY program_cmr parse failure")
	}
	copy(programCMR[:], cmrBytes)

	stateLenU64, stateLenVarintBytes, err := readCompactSize(covenantData, &off)
	if err != nil {
		return programCMR, nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY state_len parse failure")
	}
	if stateLenU64 > MAX_SIMPLICITY_STATE_BYTES {
		return programCMR, nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY state_len too large")
	}
	stateLen := int(stateLenU64)

	state, err := readBytes(covenantData, &off, stateLen)
	if err != nil {
		return programCMR, nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY state parse failure")
	}
	if len(covenantData) != 32+stateLenVarintBytes+stateLen {
		return programCMR, nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY covenant_data length mismatch")
	}
	return programCMR, state, nil
}

func validateCoreSimplicityDeploymentActive(height uint64, provider SimplicityDeploymentProvider) error {
	if provider == nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment not active")
	}
	active, err := provider.SimplicityActiveAtHeight(height)
	if err != nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment lookup failure")
	}
	if !active {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment not active")
	}
	return nil
}
