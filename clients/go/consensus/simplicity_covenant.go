package consensus

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
)

// SimplicityDeploymentProvider supplies the raw published CORE_SIMPLICITY
// deployment set and its published set anchor (§23.2.4). It does pure I/O: it
// MUST return the COMPLETE published set INCLUDING invalid descriptors and MUST
// NOT pre-filter — the consensus layer verifies the set anchor and derives the
// valid subset (validity-agnostic ordering). ok=false signals the set is
// unobtainable / only partially known (deployment state UNKNOWN).
type SimplicityDeploymentProvider interface {
	PublishedSimplicityDeployments() (descriptors []SimplicityDeploymentDescriptor, setAnchor [32]byte, ok bool, err error)
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

// SimplicityActiveAtHeight reports whether a verified CORE_SIMPLICITY surface
// governs at height on the validating chain. STATELESS and fail-closed: a provider
// I/O error is the ONE distinct disposition (returned as an error → "deployment
// lookup failure"); every other non-affirmative state — ok=false, set-anchor
// mismatch/duplicate, or no governing descriptor — collapses to (false, nil). The
// output does NOT distinguish "UNKNOWN" from "not active" (both are inactive here).
// Not deactivating an ALREADY-active surface on a later UNKNOWN lookup is a
// STATEFUL live-spend property owned by the RUB-601 call-site, not enforced here.
func SimplicityActiveAtHeight(chainID [32]byte, height uint64, provider SimplicityDeploymentProvider) (bool, error) {
	if provider == nil {
		return false, nil
	}
	descriptors, setAnchor, ok, err := provider.PublishedSimplicityDeployments()
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	surface, err := selectGoverningSurface(descriptors, setAnchor, chainID, height, liveArtifactHashes())
	if err != nil {
		return false, nil
	}
	return surface != nil, nil
}

func validateCoreSimplicityDeploymentActive(chainID [32]byte, height uint64, provider SimplicityDeploymentProvider) error {
	active, err := SimplicityActiveAtHeight(chainID, height, provider)
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

// validateCoreSimplicitySpend runs §14.3 steps 4-7 for one CORE_SIMPLICITY input:
// decode against the covenant program_cmr, then evaluate under the RUB-614 EvalHost
// bound to the built tx context and this input's eager digest32/sighash_type.
// inputIdx/digest32 are supplied by the caller (digest32 via SighashV1DigestWithType).
// NON-LIVE: no production dispatch calls this yet — the RUB-615 gate wires it.
func validateCoreSimplicitySpend(entry UtxoEntry, witness WitnessItem, inputIdx uint16, digest32 [32]byte, txContext simplicityTxContextProvider) error {
	envelope, err := parseCoreSimplicityWitnessEnvelope(witness)
	if err != nil {
		return err
	}
	_, sighashType, err := extractCryptoSigAndSighash(witness)
	if err != nil {
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
	// The tx context + host are only needed to EVALUATE (§14.3 steps 5-7), so resolve
	// them after decode: a decode/cmr failure surfaces without a context.
	ctx, err := resolveSimplicityTxContext(txContext)
	if err != nil {
		return err
	}
	host, err := newSimplicityEvalHost(ctx, inputIdx, sighashType, digest32)
	if err != nil {
		return err
	}
	if _, err := program.Evaluate(simplicity.EvalOptions{Host: host}); err != nil {
		return simplicityEvalError(err)
	}
	return nil
}

func resolveSimplicityTxContext(txContext simplicityTxContextProvider) (*SimplicityTxContext, error) {
	if txContext == nil {
		return nil, txerr(TX_ERR_PARSE, "CORE_SIMPLICITY txcontext missing")
	}
	ctx, err := txContext()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, txerr(TX_ERR_PARSE, "CORE_SIMPLICITY txcontext missing")
	}
	return ctx, nil
}

func simplicityEvalError(err error) error {
	var simErr *simplicity.Error
	if errors.As(err, &simErr) {
		return txerr(ErrorCode(simErr.Code), "")
	}
	return err
}
