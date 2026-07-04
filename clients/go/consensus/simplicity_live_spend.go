package consensus

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"

// This file holds the RUB-615 CORE_SIMPLICITY live-spend evaluation: the shared per-input helper
// wired into all four production dispatch paths, and the §14.3 steps 1-7 validator it calls. The
// §23.2.4 deployment surface + covenant-data parsing live in simplicity_covenant.go.

// coreSimplicitySpendValidation carries everything a §14.3 CORE_SIMPLICITY live spend needs at any
// dispatch path (sequential / queued / parallel worker / precompute), mirroring
// coreStealthSpendValidation. resolvedInputs is the WHOLE tx's resolved input set: SimplicityTxContext
// needs the full input and output views (same-CMR group, indexed IO, descriptor-hash), not just this
// input's entry.
type coreSimplicitySpendValidation struct {
	entry          UtxoEntry
	witness        WitnessItem
	tx             *Tx
	inputIndex     uint32
	inputValue     uint64
	chainID        [32]byte
	blockHeight    uint64
	cache          *SighashV1PrehashCache
	rotation       RotationProvider
	resolvedInputs []UtxoEntry
}

// validateCoreSimplicitySpendAtHeight runs the §23.2.4 activation gate then §14.3 steps 1-7 for one
// CORE_SIMPLICITY input. Fail-closed: unless the verified deployment surface is active at height the
// spend is REJECTED, never evaluated. On active it computes digest32 EAGERLY (reusing the existing
// SighashV1DigestWithType path — NOT a new digest) and threads it + a per-tx SimplicityTxContext into
// the RUB-614 host adapter (which builds a FRESH per-input meter).
//
// Ordering note: step 1 (suite_id != 0xF0 → TX_ERR_SIG_ALG_INVALID) is applied via
// parseCoreSimplicityWitnessEnvelope BEFORE step 2 (trailing sighash byte → TX_ERR_SIGHASH_TYPE_INVALID)
// via extractCryptoSigAndSighash, so a witness violating both surfaces step 1 first. validateCoreSimplicitySpend
// re-walks steps 1-7 with the eager digest; the pre-parse here only orders the digest's step-2 dependency.
func validateCoreSimplicitySpendAtHeight(v coreSimplicitySpendValidation) error {
	if err := validateCoreSimplicityDeploymentActive(v.chainID, v.blockHeight, simplicityDeploymentFromRotation(v.rotation)); err != nil {
		return err
	}
	// EAGER §2.4 step-3d context construction (STATE_MACHINE §3.4, BINDING): the input-side same-CMR
	// group cap fires HERE — before any per-input §14.3 error (steps 1-7) — so a group-cap rejection
	// deterministically precedes a lower-wire-index input's sighash/decode error, matching the spec
	// order. Building the context before parse also makes it the single §14.3 pre-step (the trivial
	// provider below just hands the already-built context to the shared step-1..7 validator).
	ctx, err := BuildSimplicityTxContext(v.tx, v.resolvedInputs, v.blockHeight, v.chainID)
	if err != nil {
		return err
	}
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
		return ctx, nil
	})
}

// simplicitySpendDigest computes the eager §12.2 sighash digest for a CORE_SIMPLICITY input, using the
// prehash cache when the caller supplies one (parallel/queued paths) and the direct path otherwise.
func simplicitySpendDigest(cache *SighashV1PrehashCache, tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, sighashType uint8) ([32]byte, error) {
	if cache != nil {
		return SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, sighashType)
	}
	return SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, sighashType)
}

// validateCoreSimplicitySpend runs §14.3 steps 1-7 for one CORE_SIMPLICITY input: envelope/suite
// (step 1), sighash byte (step 2), the relocated size bounds (step 3), decode against the covenant
// program_cmr (step 4), then evaluate under the RUB-614 EvalHost bound to the built tx context and
// this input's eager digest32/sighash_type (steps 5-7). inputIdx/digest32 are supplied by the caller
// (digest32 via SighashV1DigestWithType). LIVE behind the activation gate: validateCoreSimplicitySpendAtHeight
// calls this only after validateCoreSimplicityDeploymentActive reports the §23.2.4 surface active.
func validateCoreSimplicitySpend(entry UtxoEntry, witness WitnessItem, inputIdx uint16, digest32 [32]byte, txContext simplicityTxContextProvider) error {
	envelope, err := parseCoreSimplicityWitnessEnvelope(witness)
	if err != nil {
		return err
	}
	_, sighashType, err := extractCryptoSigAndSighash(witness)
	if err != nil {
		return err
	}
	// §14.3 step 3: policy size bounds, RELOCATED here from §5.4 parse (RUB-615). Program bound is
	// applied first, then envelope, per the spec's listed order — so a dual-violation surfaces
	// PROGRAM_TOO_LARGE. envelope bytes == crypto_sig == signature[:len-1] (the §12 sighash byte
	// is excluded); parse already guaranteed len(signature) >= 2, so len-1 >= 1.
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

// evaluateCoreSimplicityProgram runs §14.3 steps 5-7 for a decoded program: resolve the tx context,
// build the FRESH per-input host, and evaluate. The context is resolved only after decode so a
// decode/cmr failure surfaces without one.
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
