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

func rejectCoreSimplicitySpend() error {
	return txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
}

func rejectCoreSimplicitySpendIfPresent(inputs []UtxoEntry) error {
	for _, input := range inputs {
		if input.CovenantType == COV_TYPE_CORE_SIMPLICITY {
			return rejectCoreSimplicitySpend()
		}
	}
	return nil
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

type simplicityTxContextProvider func() (*SimplicityTxContext, error)

func parseCoreSimplicityWitnessEnvelope(witness WitnessItem) (parsedSimplicityEnvelope, error) {
	if witness.SuiteID != SUITE_ID_SIMPLICITY_ENVELOPE {
		return parsedSimplicityEnvelope{}, txerr(TX_ERR_SIG_ALG_INVALID, "CORE_SIMPLICITY witness suite must be 0xF0")
	}
	if len(witness.Pubkey) != 0 {
		return parsedSimplicityEnvelope{}, txerr(TX_ERR_PARSE, "non-canonical Simplicity envelope witness item")
	}
	return parseSimplicityEnvelopeSignature(witness.Signature)
}

func validateCoreSimplicitySpend(entry UtxoEntry, witness WitnessItem, txContext simplicityTxContextProvider) error {
	envelope, err := parseCoreSimplicityWitnessEnvelope(witness)
	if err != nil {
		return err
	}
	if _, _, err := extractCryptoSigAndSighash(witness); err != nil {
		return err
	}
	if err := requireSimplicityTxContext(txContext); err != nil {
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
	_, err = program.Evaluate(simplicity.EvalOptions{})
	if err != nil {
		return simplicityEvalError(err)
	}
	return nil
}

func requireSimplicityTxContext(txContext simplicityTxContextProvider) error {
	if txContext == nil {
		return txerr(TX_ERR_PARSE, "CORE_SIMPLICITY txcontext missing")
	}
	ctx, err := txContext()
	if err != nil {
		return err
	}
	if ctx == nil {
		return txerr(TX_ERR_PARSE, "CORE_SIMPLICITY txcontext missing")
	}
	return nil
}

func simplicityEvalError(err error) error {
	var simErr *simplicity.Error
	if errors.As(err, &simErr) {
		return txerr(ErrorCode(simErr.Code), "")
	}
	return err
}
