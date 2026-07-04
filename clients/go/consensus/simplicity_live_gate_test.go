package consensus

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
)

// RUB-615 live-gate acceptance corpus: exercises the §14.3 CORE_SIMPLICITY live spend end-to-end
// through the production dispatch paths (sequential apply + parallel work-queue) with an ACTIVE
// §23.2.4 deployment surface, plus the pre-activation fail-closed reject.

// activeSimplicityRotation reports CORE_SIMPLICITY active at activeHeight for chainID; it implements
// both RotationProvider and SimplicityDeploymentProvider (see testRotationProvider).
func activeSimplicityRotation(chainID [32]byte, activeHeight uint64) RotationProvider {
	return testRotationProvider{createSuiteID: SUITE_ID_ML_DSA_87, simplicityActiveHeight: activeHeight, chainID: chainID}
}

// simplicityAcceptWitness returns a WitnessItem carrying the given 0xF0 envelope signature.
func simplicityAcceptWitnessSig(sig []byte) WitnessItem {
	return WitnessItem{SuiteID: SUITE_ID_SIMPLICITY_ENVELOPE, Signature: append([]byte(nil), sig...)}
}

// simplicityLiveTx builds an n-input tx whose inputs each spend a CORE_SIMPLICITY accept-CMR utxo
// carrying sig, with one P2PK output. The *Tx is returned already-assembled (apply-level).
func simplicityLiveTx(inputs int, sig []byte) (*Tx, [32]byte, map[Outpoint]UtxoEntry) {
	txinputs := make([]TxInput, inputs)
	witnesses := make([]WitnessItem, inputs)
	utxos := make(map[Outpoint]UtxoEntry, inputs)
	for i := 0; i < inputs; i++ {
		prev := hashWithPrefix(byte(0x90 + i))
		txinputs[i] = TxInput{PrevTxid: prev, PrevVout: 0}
		utxos[Outpoint{Txid: prev, Vout: 0}] = coreSimplicityAcceptEntry(100)
		witnesses[i] = simplicityAcceptWitnessSig(sig)
	}
	tx := &Tx{
		Version: TX_WIRE_VERSION, TxKind: 0x00, TxNonce: 1,
		Inputs:  txinputs,
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Witness: witnesses,
	}
	return tx, hashWithPrefix(0x9f), utxos
}

func runSimplicitySeq(tx *Tx, txid [32]byte, utxos map[Outpoint]UtxoEntry, height uint64, chainID [32]byte, rot RotationProvider) error {
	_, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext(tx, txid, utxos, height, 0, chainID, rot, nil)
	return err
}

// runSimplicitySeqNoMutate asserts the §14.3 "no state mutation on a failed spend" invariant: on any
// error the sequential apply returns nil work + nil summary.
func runSimplicitySeqNoMutate(t *testing.T, tx *Tx, txid [32]byte, utxos map[Outpoint]UtxoEntry, height uint64, chainID [32]byte, rot RotationProvider) error {
	t.Helper()
	work, summary, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext(tx, txid, utxos, height, 0, chainID, rot, nil)
	if err != nil && (work != nil || summary != nil) {
		t.Fatalf("failed spend mutated state: work=%v summary=%v err=%v", work, summary, err)
	}
	return err
}

func runSimplicityPar(tx *Tx, txid [32]byte, utxos map[Outpoint]UtxoEntry, height uint64, chainID [32]byte, rot RotationProvider) error {
	q := NewSigCheckQueue(1)
	_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, height, 0, chainID, q, rot, nil)
	return err
}

// TestSimplicityLiveGate_ActivationBoundary: H-1 rejects fail-closed ("deployment not active");
// H and H+1 accept a valid spend once the §23.2.4 surface is active. Via the sequential production
// path with a test-local injected activation height (no production H_simplicity pin). The spend uses
// the accept program 0x24 — proving the activation gate lets EVALUATION run when active and rejects
// before it when inactive. The dispatch registry decodes only 0x24/0x60, so a context-intrinsic-reading
// program is not constructible here; the host actually threading and reading the tx context is proven
// end-to-end by the RUB-614 EvalHost adapter tests (simplicity_evalhost_test.go).
func TestSimplicityLiveGate_ActivationBoundary(t *testing.T) {
	var chainID [32]byte
	const H = 10
	rot := activeSimplicityRotation(chainID, H)
	sig := simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL)

	tx, txid, utxos := simplicityLiveTx(1, sig)
	assertTxErrCodeMsg(t, runSimplicitySeq(tx, txid, utxos, H-1, chainID, rot),
		TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment not active")

	for _, h := range []uint64{H, H + 1} {
		tx, txid, utxos := simplicityLiveTx(1, sig)
		if err := runSimplicitySeq(tx, txid, utxos, h, chainID, rot); err != nil {
			t.Fatalf("height %d: active accept spend rejected: %v", h, err)
		}
	}
}

// TestSimplicityLiveGate_SequentialEqualsParallel: an active accept spend and a pre-activation reject
// resolve identically on the sequential apply path and the parallel work-queue path.
func TestSimplicityLiveGate_SequentialEqualsParallel(t *testing.T) {
	var chainID [32]byte
	const H = 10
	rot := activeSimplicityRotation(chainID, H)
	sig := simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL)

	for _, tc := range []struct {
		name   string
		height uint64
		accept bool
	}{
		{"active_accept", H, true},
		{"pre_activation_reject", H - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			txA, txidA, utxosA := simplicityLiveTx(1, sig)
			txB, txidB, utxosB := simplicityLiveTx(1, sig)
			seqErr := runSimplicitySeq(txA, txidA, utxosA, tc.height, chainID, rot)
			parErr := runSimplicityPar(txB, txidB, utxosB, tc.height, chainID, rot)
			if (seqErr == nil) != (parErr == nil) {
				t.Fatalf("seq/par accept divergence: seq=%v par=%v", seqErr, parErr)
			}
			if tc.accept && seqErr != nil {
				t.Fatalf("expected accept, got seq=%v par=%v", seqErr, parErr)
			}
			if !tc.accept {
				assertTxErrCode(t, seqErr, TX_ERR_COVENANT_TYPE_INVALID)
				assertTxErrCode(t, parErr, TX_ERR_COVENANT_TYPE_INVALID)
			}
		})
	}
}

// TestSimplicityLiveGate_Step3SizeBounds: the relocated §14.3 step-3 policy bounds fire at spend time
// (not parse), program-first then envelope. Observed end-to-end through the production apply path with
// an active surface (a well-formed but oversized envelope now PASSES §5.4 parse — RUB-615 relocation).
func TestSimplicityLiveGate_Step3SizeBounds(t *testing.T) {
	var chainID [32]byte
	const H = 1
	rot := activeSimplicityRotation(chainID, H)

	bigProgram := make([]byte, MAX_SIMPLICITY_PROGRAM_BYTES+1)
	okProgram := make([]byte, MAX_SIMPLICITY_PROGRAM_BYTES)
	bigWitness := make([]byte, MAX_SIMPLICITY_ENVELOPE_BYTES)

	// program just over MAX_SIMPLICITY_PROGRAM_BYTES -> PROGRAM_TOO_LARGE (program bound is first).
	tx, txid, utxos := simplicityLiveTx(1, simplicityEnvelopeSignature(bigProgram, nil, SIGHASH_ALL))
	assertTxErrCode(t, runSimplicitySeqNoMutate(t, tx, txid, utxos, H, chainID, rot), TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE)

	// program at bound but the witness pushes the envelope just over MAX_SIMPLICITY_ENVELOPE_BYTES ->
	// ENVELOPE_TOO_LARGE (program bound satisfied, so the envelope bound is the first failure).
	tx, txid, utxos = simplicityLiveTx(1, simplicityEnvelopeSignature(okProgram, bigWitness, SIGHASH_ALL))
	assertTxErrCode(t, runSimplicitySeqNoMutate(t, tx, txid, utxos, H, chainID, rot), TX_ERR_SIMPLICITY_ENVELOPE_TOO_LARGE)

	// E4 dual-violation: BOTH program and envelope over bound -> PROGRAM_TOO_LARGE (program checked first).
	tx, txid, utxos = simplicityLiveTx(1, simplicityEnvelopeSignature(bigProgram, bigWitness, SIGHASH_ALL))
	assertTxErrCode(t, runSimplicitySeqNoMutate(t, tx, txid, utxos, H, chainID, rot), TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE)

	// E4 mixed-error: bad sighash byte + oversized envelope -> SIGHASH_TYPE_INVALID (step 2 precedes step 3).
	mixed := simplicityEnvelopeSignature(bigProgram, bigWitness, SIGHASH_ALL)
	mixed[len(mixed)-1] = 0x7f // invalid trailing sighash byte
	tx, txid, utxos = simplicityLiveTx(1, mixed)
	assertTxErrCode(t, runSimplicitySeqNoMutate(t, tx, txid, utxos, H, chainID, rot), TX_ERR_SIGHASH_TYPE_INVALID)

	// End-to-end through FULL TX PARSE (no direct-call stub): the relocation means §5.4 parse now
	// ACCEPTS the oversized PROGRAM, and the production connect path rejects it at §14.3 step 3.
	prev := hashWithPrefix(0xB0)
	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData(),
		[]WitnessItem{simplicityAcceptWitnessSig(simplicityEnvelopeSignature(bigProgram, nil, SIGHASH_ALL))})
	parsedTx, parsedTxid := mustParseTxForUtxo(t, txBytes) // parse must accept the oversized program
	parseUtxos := map[Outpoint]UtxoEntry{{Txid: prev, Vout: 0}: coreSimplicityAcceptEntry(100)}
	assertTxErrCode(t, runSimplicitySeqNoMutate(t, parsedTx, parsedTxid, parseUtxos, H, chainID, rot), TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE)

	// Symmetric full-parse case for the ENVELOPE bound: program within bound, an oversized witness
	// pushes the envelope over MAX_SIMPLICITY_ENVELOPE_BYTES. §5.4 parse must still ACCEPT, and the
	// production connect path rejects at §14.3 step 3 with ENVELOPE_TOO_LARGE.
	envBytes := txWithOneInputOneOutputWithWitness(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData(),
		[]WitnessItem{simplicityAcceptWitnessSig(simplicityEnvelopeSignature(okProgram, bigWitness, SIGHASH_ALL))})
	parsedEnvTx, parsedEnvTxid := mustParseTxForUtxo(t, envBytes) // parse must accept the oversized envelope
	assertTxErrCode(t, runSimplicitySeqNoMutate(t, parsedEnvTx, parsedEnvTxid, parseUtxos, H, chainID, rot), TX_ERR_SIMPLICITY_ENVELOPE_TOO_LARGE)
}

// TestSimplicityLiveGate_EngineErrorMapping (E4 steps 6-7): the engine's ErrBudgetExceeded / ErrRejected
// outcomes map to the public step-6/step-7 TX codes via simplicityEvalError. These outcomes are engine
// internals (covered end-to-end in simplicity/program_test.go with mock hosts) and are not reachable
// through the dispatch registry, whose only decodable programs are accept (0x24) and the sha3 jet
// (0x60); RUB-615 owns the error-code MAPPING, asserted here.
func TestSimplicityLiveGate_EngineErrorMapping(t *testing.T) {
	assertTxErrCode(t, simplicityEvalError(&simplicity.Error{Code: simplicity.ErrBudgetExceeded}), TX_ERR_SIMPLICITY_BUDGET_EXCEEDED)
	assertTxErrCode(t, simplicityEvalError(&simplicity.Error{Code: simplicity.ErrRejected}), TX_ERR_SIMPLICITY_REJECTED)
}

// TestSimplicityLiveGate_OrderedErrorSet: §14.3 first-error set steps 1/2/4/5 (suite, sighash, cmr,
// jet) surface the lowest step's error through the production apply path. Step 3 size ordering is in
// TestSimplicityLiveGate_Step3SizeBounds; steps 6/7 (budget/reject) are engine outcomes mapped in
// TestSimplicityLiveGate_EngineErrorMapping. The lowest
// step's error, observed through the production apply path with an active surface.
func TestSimplicityLiveGate_OrderedErrorSet(t *testing.T) {
	var chainID [32]byte
	const H = 1
	rot := activeSimplicityRotation(chainID, H)

	for _, tc := range []struct {
		name    string
		witness []byte // 0xF0 envelope signature; empty means "use a non-0xF0 sentinel witness"
		entry   func() UtxoEntry
		code    ErrorCode
	}{
		{"step1_suite", nil, func() UtxoEntry { return coreSimplicityAcceptEntry(100) }, TX_ERR_SIG_ALG_INVALID},
		{"step2_sighash", func() []byte {
			s := simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL)
			s[len(s)-1] = 0x7f
			return s
		}(), func() UtxoEntry { return coreSimplicityAcceptEntry(100) }, TX_ERR_SIGHASH_TYPE_INVALID},
		{
			// step4 DECODE precedes CMR comparison: an undecodable selector (0x25) fails structurally
			// before any program_cmr check (§14.3:1578-1583).
			"step4_decode", simplicityEnvelopeSignature([]byte{0x25}, nil, SIGHASH_ALL),
			func() UtxoEntry { return coreSimplicityAcceptEntry(100) }, TX_ERR_SIMPLICITY_DECODE,
		},
		{
			"step4_cmr_mismatch", simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL),
			func() UtxoEntry {
				return UtxoEntry{Value: 100, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: encodeSimplicityCovenantData([32]byte{0x99}, nil)}
			}, TX_ERR_SIMPLICITY_CMR_MISMATCH,
		},
		{
			"step5_jet_disallowed", simplicityEnvelopeSignature([]byte{0x60}, nil, SIGHASH_ALL),
			func() UtxoEntry {
				return UtxoEntry{Value: 100, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: encodeSimplicityCovenantData([32]byte{0x39, 0x99, 0x88, 0x9b, 0xdf, 0x18, 0xd0, 0x7c, 0x6c, 0x38, 0xb7, 0xaa, 0xcb, 0x89, 0xf6, 0xc2, 0xbd, 0xd3, 0xc6, 0xa5, 0xc3, 0xc9, 0x3c, 0xe7, 0x9d, 0x19, 0x02, 0xa5, 0x67, 0xb1, 0xe6, 0x37}, nil)}
			}, TX_ERR_SIMPLICITY_JET_DISALLOWED,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := hashWithPrefix(0xA0)
			w := simplicityAcceptWitnessSig(tc.witness)
			if tc.witness == nil {
				w = WitnessItem{SuiteID: SUITE_ID_SENTINEL}
			}
			tx := &Tx{
				Version: TX_WIRE_VERSION, TxKind: 0x00, TxNonce: 1,
				Inputs:  []TxInput{{PrevTxid: prev, PrevVout: 0}},
				Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
				Witness: []WitnessItem{w},
			}
			utxos := map[Outpoint]UtxoEntry{{Txid: prev, Vout: 0}: tc.entry()}
			assertTxErrCode(t, runSimplicitySeq(tx, hashWithPrefix(0xA1), utxos, H, chainID, rot), tc.code)
		})
	}
}

// TestSimplicityLiveGate_InputGroupCap (E10): a same-CMR group of CORE_SIMPLICITY inputs exceeding
// SIMPLICITY_MAX_GROUP_INPUTS rejects the WHOLE tx TX_ERR_COVENANT_TYPE_INVALID (atomic discard),
// observed live on both the sequential and parallel paths.
func TestSimplicityLiveGate_InputGroupCap(t *testing.T) {
	var chainID [32]byte
	const H = 1
	rot := activeSimplicityRotation(chainID, H)
	sig := simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL)

	// At the cap: accepts. One over: whole-tx reject.
	txOK, txidOK, utxosOK := simplicityLiveTx(SIMPLICITY_MAX_GROUP_INPUTS, sig)
	if err := runSimplicitySeq(txOK, txidOK, utxosOK, H, chainID, rot); err != nil {
		t.Fatalf("group at cap should accept, got %v", err)
	}
	txOver, txidOver, utxosOver := simplicityLiveTx(SIMPLICITY_MAX_GROUP_INPUTS+1, sig)
	assertTxErrCode(t, runSimplicitySeq(txOver, txidOver, utxosOver, H, chainID, rot), TX_ERR_COVENANT_TYPE_INVALID)
	txOverP, txidOverP, utxosOverP := simplicityLiveTx(SIMPLICITY_MAX_GROUP_INPUTS+1, sig)
	assertTxErrCode(t, runSimplicityPar(txOverP, txidOverP, utxosOverP, H, chainID, rot), TX_ERR_COVENANT_TYPE_INVALID)
}

// TestSimplicityLiveGate_PerInputFreshHost: two CORE_SIMPLICITY inputs sharing the accept CMR (a
// 2-member group under the cap) each evaluate under their OWN freshly built EvalHost — the dispatch
// constructs a per-input host rather than reusing one. This exercises the per-input host wiring; it
// does NOT exercise budget-sharing: the only dispatch-decodable programs (accept 0x24 and the sha3
// jet 0x60) both cost far below MaxExecCost, so a shared vs fresh meter is indistinguishable at this
// layer. Fresh-meter budget isolation itself is proven at the engine level in
// simplicity/program_test.go (RUB-598); here we only pin that both inputs are independently accepted.
func TestSimplicityLiveGate_PerInputFreshHost(t *testing.T) {
	var chainID [32]byte
	const H = 1
	rot := activeSimplicityRotation(chainID, H)
	sig := simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL)

	// Two inputs, same accept CMR (a 2-member group, under the cap): each must evaluate to accept
	// under its own freshly built per-input host.
	tx, txid, utxos := simplicityLiveTx(2, sig)
	if err := runSimplicitySeq(tx, txid, utxos, H, chainID, rot); err != nil {
		t.Fatalf("two-input per-input-host accept rejected: %v", err)
	}
}

// TestSimplicityLiveGate_VersionByteStaysParseError (E17): a 0xF0 envelope version byte != 0x01 stays
// a parse-stage TX_ERR_PARSE (the relocation kept the version check structural in §5.4 parse).
func TestSimplicityLiveGate_VersionByteStaysParseError(t *testing.T) {
	badVersion := simplicityEnvelopeSignatureWithVersion(0x02, []byte{0x24}, nil, SIGHASH_ALL)
	if _, err := parseSimplicityEnvelopeSignature(badVersion); err == nil {
		t.Fatal("version != 0x01 must stay parse-stage TX_ERR_PARSE")
	} else {
		assertTxErrCode(t, err, TX_ERR_PARSE)
	}
}

// TestSimplicityLiveGate_NoMutationBothPaths: a failed active spend mutates NO state on EITHER the
// sequential apply path or the parallel work-queue path (the §14.3 "no state mutation on a failed
// spend" invariant, proven symmetrically).
func TestSimplicityLiveGate_NoMutationBothPaths(t *testing.T) {
	var chainID [32]byte
	const H = 1
	rot := activeSimplicityRotation(chainID, H)
	badSig := simplicityEnvelopeSignature(make([]byte, MAX_SIMPLICITY_PROGRAM_BYTES+1), nil, SIGHASH_ALL)

	tx, txid, utxos := simplicityLiveTx(1, badSig)
	seqWork, seqSummary, seqErr := ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext(tx, txid, utxos, H, 0, chainID, rot, nil)
	if seqErr == nil || seqWork != nil || seqSummary != nil {
		t.Fatalf("sequential failed spend mutated: work=%v summary=%v err=%v", seqWork, seqSummary, seqErr)
	}

	tx, txid, utxos = simplicityLiveTx(1, badSig)
	q := NewSigCheckQueue(1)
	parWork, parFee, parErr := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, H, 0, chainID, q, rot, nil)
	if parErr == nil || parWork != nil || parFee != 0 || q.Len() != 0 {
		t.Fatalf("parallel failed spend mutated: work=%v fee=%d sigs=%d err=%v", parWork, parFee, q.Len(), parErr)
	}
}

// TestSimplicityLiveGate_PrecomputeResolvesSimplicity: after removing the StoppedAtCoreSimplicity
// flag, PrecomputeTxContexts resolves a CORE_SIMPLICITY input as a normal 1-slot input (witness
// assigned, resolution continues) rather than stopping — so the precompute path reaches the worker's
// §14.3 gate. (Precompute is structural: the activation gate runs in the worker, not here.)
func TestSimplicityLiveGate_PrecomputeResolvesSimplicity(t *testing.T) {
	simpPrev := sha3_256([]byte("precompute-live-simplicity"))
	utxos := map[Outpoint]UtxoEntry{{Txid: simpPrev, Vout: 0}: coreSimplicityAcceptEntry(100)}
	tx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: simpPrev, PrevVout: 0}},
		Outputs: []TxOutput{{Value: 50, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Witness: []WitnessItem{simplicityAcceptWitnessSig(simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL))},
	}
	pb := makeParsedBlockForPrecompute(makeSimpleCoinbase(), []*Tx{tx})
	ctxs, err := PrecomputeTxContexts(pb, utxos, 100)
	if err != nil {
		t.Fatalf("precompute rejected a resolvable simplicity input: %v", err)
	}
	if len(ctxs) != 1 || len(ctxs[0].ResolvedInputs) != 1 || ctxs[0].ResolvedInputs[0].CovenantType != COV_TYPE_CORE_SIMPLICITY {
		t.Fatalf("precompute did not resolve the simplicity input as expected: %+v", ctxs)
	}
}

// TestSimplicityLiveGate_GroupCapPrecedesPerInputError (E10 + one_invariant ordering, STATE_MACHINE
// §2.4 step-3d / §3.4 BINDING): the input-side same-CMR group cap is constructed EAGERLY and
// deterministically precedes any per-input §14.3 error, so a same-CMR group over the cap rejects the
// whole tx TX_ERR_COVENANT_TYPE_INVALID even when the lowest-wire-index input ALSO has a §14.3 step-2
// (sighash) or step-4 (decode) error.
func TestSimplicityLiveGate_GroupCapPrecedesPerInputError(t *testing.T) {
	var chainID [32]byte
	const H = 1
	rot := activeSimplicityRotation(chainID, H)
	goodSig := simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL)

	badFirst := func(firstSig []byte) (*Tx, [32]byte, map[Outpoint]UtxoEntry) {
		tx, txid, utxos := simplicityLiveTx(SIMPLICITY_MAX_GROUP_INPUTS+1, goodSig)
		tx.Witness[0] = simplicityAcceptWitnessSig(firstSig)
		return tx, txid, utxos
	}

	// input 0 has a bad trailing sighash byte (§14.3 step 2) — group cap still wins.
	badSighash := append([]byte(nil), goodSig...)
	badSighash[len(badSighash)-1] = 0x7f
	tx, txid, utxos := badFirst(badSighash)
	assertTxErrCode(t, runSimplicitySeqNoMutate(t, tx, txid, utxos, H, chainID, rot), TX_ERR_COVENANT_TYPE_INVALID)

	// input 0 carries an undecodable selector 0x25 (§14.3 step 4 decode) — group cap still wins.
	tx, txid, utxos = badFirst(simplicityEnvelopeSignature([]byte{0x25}, nil, SIGHASH_ALL))
	assertTxErrCode(t, runSimplicitySeqNoMutate(t, tx, txid, utxos, H, chainID, rot), TX_ERR_COVENANT_TYPE_INVALID)
}
