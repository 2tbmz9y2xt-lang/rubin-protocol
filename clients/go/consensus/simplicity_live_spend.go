package consensus

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"

// This file holds the RUB-615 CORE_SIMPLICITY live-spend evaluation: the §2.4 step-3d context build,
// the per-input dispatch helper, and the §14.3 steps 1-7 validator (deployment/parse in simplicity_covenant.go).

// coreSimplicitySpendValidation carries what a §14.3 CORE_SIMPLICITY spend needs at any dispatch path.
// txContext is the ONE immutable per-tx SimplicityTxContext built EAGERLY at §2.4 step 3d by the caller
// (group cap already enforced); per-input validation only threads it into the §14.3 walk.
type coreSimplicitySpendValidation struct {
	entry       UtxoEntry
	witness     WitnessItem
	tx          *Tx
	inputIndex  uint32
	inputValue  uint64
	chainID     [32]byte
	blockHeight uint64
	cache       *SighashV1PrehashCache
	txContext   *SimplicityTxContext
}

// validateCoreSimplicitySpendAtHeight runs §14.3 steps 1-7 for one CORE_SIMPLICITY input. The §23.2.4
// activation gate and the §2.4 step-3d group cap were already enforced EAGERLY by the caller
// (buildSimplicityStep3dContext), so this runs only for an active deployment. It computes digest32
// eagerly (reusing SighashV1DigestWithType — NOT a new digest) and threads it + the pre-built per-tx
// SimplicityTxContext into the RUB-614 host adapter (FRESH per-input meter); step 1 (suite_id) before step 2 (sighash byte).
func validateCoreSimplicitySpendAtHeight(v coreSimplicitySpendValidation) error {
	if _, err := parseCoreSimplicityWitnessEnvelope(v.witness); err != nil {
		return err
	}
	_, sighashType, err := extractCryptoSigAndSighash(v.witness)
	if err != nil {
		return err
	}
	digest32, err := simplicitySpendDigest(v.cache, v.tx, v.inputIndex, v.inputValue, v.chainID, sighashType)
	if err != nil {
		return err
	}
	return validateCoreSimplicitySpend(v.entry, v.witness, uint16(v.inputIndex), digest32, func() (*SimplicityTxContext, error) {
		return v.txContext, nil
	})
}

// buildSimplicityStep3dContext performs §2.4 step 3d EAGERLY (every dispatch path runs it after input
// resolution, before the spend loop): no-op when no CORE_SIMPLICITY input; else the §23.2.4 activation
// gate is enforced HERE at step-3d entry (checkSpendCovenant accepts CORE_SIMPLICITY at step 3), before
// the group cap — so an inactive deployment rejects ahead of the cap and every §14.3/lower-wire-index
// spend error. Lazy per-program construction is forbidden ("NOT a conforming implementation of the error order").
func buildSimplicityStep3dContext(tx *Tx, resolvedInputs []UtxoEntry, height uint64, chainID [32]byte, rotation RotationProvider) (*SimplicityTxContext, error) {
	hasSimplicity := false
	for _, e := range resolvedInputs {
		if e.CovenantType == COV_TYPE_CORE_SIMPLICITY {
			hasSimplicity = true
			break
		}
	}
	if !hasSimplicity {
		return nil, nil
	}
	if err := validateCoreSimplicityDeploymentActive(chainID, height, simplicityDeploymentFromRotation(rotation)); err != nil {
		return nil, err
	}
	return BuildSimplicityTxContext(tx, resolvedInputs, height, chainID)
}

// simplicitySpendDigest computes the eager §12.2 sighash digest for a CORE_SIMPLICITY input, using the
// prehash cache when the caller supplies one (parallel/queued paths) and the direct path otherwise.
func simplicitySpendDigest(cache *SighashV1PrehashCache, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, sighashType uint8) ([32]byte, error) {
	if cache != nil {
		return SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, sighashType)
	}
	return SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, sighashType)
}

// validateCoreSimplicitySpend runs §14.3 steps 1-7 for one CORE_SIMPLICITY input: envelope/suite (1),
// sighash byte (2), relocated size bounds (3), decode vs the covenant program_cmr (4), then evaluate
// under the RUB-614 EvalHost with the eager digest32/sighash_type (5-7). Runs only behind the gate.
func validateCoreSimplicitySpend(entry UtxoEntry, witness WitnessItem, inputIdx uint16, digest32 [32]byte, txContext simplicityTxContextProvider) error {
	envelope, err := parseCoreSimplicityWitnessEnvelope(witness)
	if err != nil {
		return err
	}
	_, sighashType, err := extractCryptoSigAndSighash(witness)
	if err != nil {
		return err
	}
	// §14.3 step 3: policy size bounds RELOCATED from §5.4 parse (RUB-615), program-first then envelope
	// (dual-violation -> PROGRAM_TOO_LARGE). envelope bytes = signature[:len-1] (sighash byte excluded).
	if len(envelope.program) > MAX_SIMPLICITY_PROGRAM_BYTES {
		return txerr(TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE, "CORE_SIMPLICITY program too large")
	}
	if len(witness.Signature)-1 > MAX_SIMPLICITY_ENVELOPE_BYTES {
		return txerr(TX_ERR_SIMPLICITY_ENVELOPE_TOO_LARGE, "CORE_SIMPLICITY envelope too large")
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
	return evaluateCoreSimplicityProgram(program, inputIdx, digest32, sighashType, txContext)
}

// evaluateCoreSimplicityProgram runs §14.3 steps 5-7: resolve the step-3d context, build the FRESH per-input host, evaluate.
func evaluateCoreSimplicityProgram(program simplicity.Program, inputIdx uint16, digest32 [32]byte, sighashType uint8, txContext simplicityTxContextProvider) error {
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
