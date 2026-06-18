package consensus

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
)

type SimplicityDeploymentProvider interface {
	SimplicityActiveAtHeight(height uint64) (bool, error)
}

func simplicityDeploymentFromRotation(rotation RotationProvider) SimplicityDeploymentProvider {
	provider, ok := rotation.(SimplicityDeploymentProvider)
	if !ok {
		return nil
	}
	return provider
}

func hasCoreSimplicityInput(inputs []UtxoEntry) bool {
	for _, input := range inputs {
		if input.CovenantType == COV_TYPE_CORE_SIMPLICITY {
			return true
		}
	}
	return false
}

func parseCoreSimplicityCovenantData(value uint64, covenantData []byte) ([32]byte, []byte, error) {
	var programCMR [32]byte
	if value == 0 {
		return programCMR, nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY value must be > 0")
	}

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

func validateCoreSimplicitySpend(entry UtxoEntry, witness WitnessItem, tx *Tx, blockHeight uint64, chainID [32]byte, resolvedInputs []UtxoEntry) error {
	if witness.SuiteID != SUITE_ID_SIMPLICITY_ENVELOPE {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_SIMPLICITY witness suite must be 0xF0")
	}
	envelope, err := parseSimplicityEnvelopeSignature(witness.Signature)
	if err != nil {
		return err
	}
	if _, err := BuildSimplicityTxContext(tx, resolvedInputs, blockHeight, chainID); err != nil {
		return err
	}
	programCMR, _, err := parseCoreSimplicityCovenantData(entry.Value, entry.CovenantData)
	if err != nil {
		return err
	}
	program, err := simplicity.Decode(envelope.program, envelope.witness, simplicity.DecodeOptions{
		SemanticsVersion:   simplicity.SemanticsVersion,
		CovenantProgramCMR: &programCMR,
	})
	if err != nil {
		return simplicityEvalError(err)
	}
	result, err := program.Evaluate(simplicity.EvalOptions{})
	if err != nil {
		return simplicityEvalError(err)
	}
	if !result.Accepted {
		return txerr(TX_ERR_SIMPLICITY_REJECTED, "CORE_SIMPLICITY program rejected")
	}
	return nil
}

func simplicityEvalError(err error) error {
	var simErr *simplicity.Error
	if errors.As(err, &simErr) {
		return txerr(ErrorCode(simErr.Code), string(simErr.Code))
	}
	return err
}
