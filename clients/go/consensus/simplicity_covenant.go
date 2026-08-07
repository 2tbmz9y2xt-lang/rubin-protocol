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

// simplicityDeploymentEvidenceAtHeight is the ONE observation that decides
// CORE_SIMPLICITY deployment state (§23.2.4). It performs EXACTLY ONE provider
// read and returns, from that same read, the governing surface (nil = not
// active), the typed cause a rejecting caller attaches, and the provider's own
// I/O error. Every consumer of deployment state in this package is expressed
// over this helper, so the evidence a caller publishes is always evidence about
// the observation that actually decided the outcome — a second provider call
// would be a DIFFERENT observation and may never authorize a disposition.
//
// Rows, in evaluation order (surface, cause, err); the node owns the mapping
// from cause to relay disposition:
//
//	provider == nil                       (nil, InactiveFrozen,   nil)
//	provider I/O error                    (nil, Unavailable,      err)
//	ok == false                           (nil, Unavailable,      nil)
//	set-anchor mismatch / duplicate       (nil, EvidenceInvalid,  nil)
//	verified set, no governing descriptor (nil, InactiveProvider, nil)
//	governing descriptor at height        (surface, Unspecified,  nil)
//
// The cause is meaningful ONLY on a non-affirmative row: the active row selects
// TxErrorCauseUnspecified because it produces no error to carry one.
func simplicityDeploymentEvidenceAtHeight(chainID [32]byte, height uint64, provider SimplicityDeploymentProvider) (*VerifiedSimplicitySurface, TxErrorCause, error) {
	if provider == nil {
		return nil, TxErrorCauseSimplicityDeploymentInactiveFrozen, nil
	}
	descriptors, setAnchor, ok, err := provider.PublishedSimplicityDeployments()
	if err != nil {
		return nil, TxErrorCauseSimplicityDeploymentUnavailable, err
	}
	if !ok {
		return nil, TxErrorCauseSimplicityDeploymentUnavailable, nil
	}
	surface, err := selectGoverningSurface(descriptors, setAnchor, chainID, height, liveArtifactHashes())
	if err != nil {
		return nil, TxErrorCauseSimplicityDeploymentEvidenceInvalid, nil
	}
	if surface == nil {
		return nil, TxErrorCauseSimplicityDeploymentInactiveProvider, nil
	}
	return surface, TxErrorCauseUnspecified, nil
}

// SimplicityActiveAtHeight reports whether a verified CORE_SIMPLICITY surface
// governs at height on the validating chain. STATELESS and fail-closed: a provider
// I/O error is the ONE distinct disposition (returned as an error → "deployment
// lookup failure"); every other non-affirmative state — ok=false, set-anchor
// mismatch/duplicate, or no governing descriptor — collapses to (false, nil). The
// output does NOT distinguish "UNKNOWN" from "not active" (both are inactive here).
// Not deactivating an ALREADY-active surface on a later UNKNOWN lookup is a
// STATEFUL live-spend property owned by the RUB-601 call-site, not enforced here.
//
// It is the evidence helper with the cause COLLAPSED away: the (bool, error)
// surface, the returned provider error value and the single provider read are
// byte-for-byte what this function did before the cause existed.
func SimplicityActiveAtHeight(chainID [32]byte, height uint64, provider SimplicityDeploymentProvider) (bool, error) {
	surface, _, err := simplicityDeploymentEvidenceAtHeight(chainID, height, provider)
	if err != nil {
		return false, err
	}
	return surface != nil, nil
}

// validateCoreSimplicityDeploymentActive is the §23.2.4 activation gate. The
// two public messages and the single public code are unchanged and still
// collapse five distinct deployment states onto two strings; the typed cause
// carries the state the strings lose, taken from the SAME read that decided the
// rejection, so no consumer has to match on message text.
func validateCoreSimplicityDeploymentActive(chainID [32]byte, height uint64, provider SimplicityDeploymentProvider) error {
	surface, cause, err := simplicityDeploymentEvidenceAtHeight(chainID, height, provider)
	if err != nil {
		return txerrWithCause(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment lookup failure", cause)
	}
	if surface == nil {
		return txerrWithCause(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment not active", cause)
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

func simplicityEvalError(err error) error {
	var simErr *simplicity.Error
	if errors.As(err, &simErr) {
		return txerr(ErrorCode(simErr.Code), "")
	}
	return err
}
