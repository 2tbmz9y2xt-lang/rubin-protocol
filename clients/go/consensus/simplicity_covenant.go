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

	off := 0
	if _, err := readBytes(covenantData, &off, 32); err != nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY program_cmr parse failure")
	}

	stateLenU64, stateLenVarintBytes, err := readCompactSize(covenantData, &off)
	if err != nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY state_len parse failure")
	}
	if stateLenU64 > MAX_SIMPLICITY_STATE_BYTES {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY state_len too large")
	}
	stateLen := int(stateLenU64)

	if _, err := readBytes(covenantData, &off, stateLen); err != nil {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY state parse failure")
	}
	if len(covenantData) != 32+stateLenVarintBytes+stateLen {
		return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY covenant_data length mismatch")
	}
	return nil
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
