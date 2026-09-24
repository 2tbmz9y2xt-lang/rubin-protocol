package consensus

import (
	"bytes"
	"context"
	"testing"
)

type nativeSuiteAvailabilityRotation struct {
	create, spend           *NativeSuiteSet
	createCalls, spendCalls int
}

func (p *nativeSuiteAvailabilityRotation) NativeCreateSuites(uint64) *NativeSuiteSet {
	if p == nil {
		return nil
	}
	p.createCalls++
	return p.create
}

func (p *nativeSuiteAvailabilityRotation) NativeSpendSuites(uint64) *NativeSuiteSet {
	if p == nil {
		return nil
	}
	p.spendCalls++
	return p.spend
}

type nativeSuiteAvailabilityFixture struct {
	entry, htlcEntry, stealthEntry UtxoEntry
	w, path                        WitnessItem
	tx                             *Tx
	cache                          *SighashV1PrehashCache
	keyID                          [32]byte
}

func newNativeSuiteAvailabilityFixture(t *testing.T) nativeSuiteAvailabilityFixture {
	t.Helper()
	entry, w, tx, cleanup := buildP2PKTestData(t, SUITE_ID_ML_DSA_87, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	t.Cleanup(cleanup)
	entry.Value = 100
	tx.Witness = []WitnessItem{w}
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}
	keyID := sha3_256(w.Pubkey)
	claimKeyID := [32]byte{0x71}
	htlcEntry := makeHTLCEntry([32]byte{0x72}, LOCK_MODE_HEIGHT, 1, claimKeyID, keyID)
	path := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: keyID[:], Signature: []byte{0x01}}
	stealthEntry := UtxoEntry{Value: 100, CovenantType: COV_TYPE_CORE_STEALTH, CovenantData: makeStealthCovenantData(keyID)}
	return nativeSuiteAvailabilityFixture{entry: entry, htlcEntry: htlcEntry, stealthEntry: stealthEntry, w: w, path: path, tx: tx, cache: cache, keyID: keyID}
}

type nativeSuiteAvailabilityOrigin struct {
	name, message string
	create        bool
	run           func(RotationProvider, *SuiteRegistry) error
}

func (f nativeSuiteAvailabilityFixture) origins() []nativeSuiteAvailabilityOrigin {
	threshold := func(context string, queued bool) func(RotationProvider, *SuiteRegistry) error {
		return func(rotation RotationProvider, registry *SuiteRegistry) error {
			if queued {
				return validateThresholdSigSpendQ([][32]byte{f.keyID}, 1, []WitnessItem{f.w}, f.tx, 0, 100, [32]byte{}, 1, f.cache, NewSigCheckQueue(1), context, rotation, registry)
			}
			return validateThresholdSigSpendAtHeight(testThresholdSigSpendCheck([][32]byte{f.keyID}, 1, []WitnessItem{f.w}, testSpendSigEnv{tx: f.tx, inputValue: 100, blockHeight: 1, cache: f.cache, rotation: rotation, registry: registry, context: context}))
		}
	}
	return []nativeSuiteAvailabilityOrigin{
		{"create_p2pk", "CORE_P2PK suite not in native create set", true, func(rotation RotationProvider, _ *SuiteRegistry) error {
			return validateP2PKGenesisOutput(TxOutput{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: f.entry.CovenantData}, 1, rotation)
		}},
		{"p2pk", "CORE_P2PK suite not in native spend set", false, func(rotation RotationProvider, registry *SuiteRegistry) error {
			return validateP2PKSpendAtHeight(testP2PKSpendCheck(f.entry, f.w, testSpendSigEnv{tx: f.tx, inputValue: 100, blockHeight: 1, cache: f.cache, rotation: rotation, registry: registry}))
		}},
		{"multisig", "CORE_MULTISIG suite not in native spend set", false, threshold("CORE_MULTISIG", false)},
		{"vault", "CORE_VAULT suite not in native spend set", false, threshold("CORE_VAULT", false)},
		{"htlc", "CORE_HTLC suite not in native spend set", false, func(rotation RotationProvider, registry *SuiteRegistry) error {
			return validateHTLCSignaturePrecheck(f.w, f.keyID, 1, rotation, registry)
		}},
		{"stealth", "CORE_STEALTH suite not in native spend set", false, func(rotation RotationProvider, registry *SuiteRegistry) error {
			return validateCoreStealthSpendAtHeight(coreStealthSpendValidation{entry: f.stealthEntry, w: f.w, tx: f.tx, inputValue: 100, blockHeight: 1, cache: f.cache, rotation: rotation, registry: registry})
		}},
		{"p2pk_q", "CORE_P2PK suite not in native spend set", false, func(rotation RotationProvider, registry *SuiteRegistry) error {
			return validateP2PKSpendQ(f.entry, f.w, f.tx, 0, 100, [32]byte{}, 1, f.cache, NewSigCheckQueue(1), rotation, registry)
		}},
		{"multisig_q", "CORE_MULTISIG suite not in native spend set", false, threshold("CORE_MULTISIG", true)},
		{"vault_q", "CORE_VAULT suite not in native spend set", false, threshold("CORE_VAULT", true)},
		{"htlc_q", "CORE_HTLC suite not in native spend set", false, func(rotation RotationProvider, registry *SuiteRegistry) error {
			return validateHTLCSpendQ(f.htlcEntry, f.path, f.w, f.tx, 0, 100, [32]byte{}, 1, 0, f.cache, NewSigCheckQueue(1), rotation, registry)
		}},
		{"stealth_q", "CORE_STEALTH suite not in native spend set", false, func(rotation RotationProvider, registry *SuiteRegistry) error {
			return validateCoreStealthSpendQ(f.stealthEntry, f.w, f.tx, 0, 100, [32]byte{}, 1, f.cache, NewSigCheckQueue(1), rotation, registry)
		}},
	}
}

func TestNativeSuiteAuthorityIncoherence(t *testing.T) {
	f := newNativeSuiteAvailabilityFixture(t)
	for _, origin := range f.origins() {
		t.Run(origin.name, func(t *testing.T) {
			rotation := &nativeSuiteAvailabilityRotation{}
			mustTxErrorCause(t, origin.run(rotation, DefaultSuiteRegistry()), TX_ERR_SIG_ALG_INVALID, origin.message, TxErrorCauseNativeSuiteSetUnavailable)
			if origin.create {
				if rotation.createCalls != 1 || rotation.spendCalls != 0 {
					t.Fatalf("provider calls create=%d spend=%d", rotation.createCalls, rotation.spendCalls)
				}
			} else if rotation.createCalls != 0 || rotation.spendCalls != 1 {
				t.Fatalf("provider calls create=%d spend=%d", rotation.createCalls, rotation.spendCalls)
			}
		})
	}

	var typedNil *nativeSuiteAvailabilityRotation
	mustTxErrorCause(t, f.origins()[0].run(typedNil, nil), TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite not in native create set", TxErrorCauseNativeSuiteSetUnavailable)
	for _, origin := range f.origins() {
		for _, tc := range []struct {
			name string
			set  *NativeSuiteSet
			pass bool
		}{
			{"empty", NewNativeSuiteSet(), false},
			{"excluding", NewNativeSuiteSet(0x02), false},
			{"including", NewNativeSuiteSet(SUITE_ID_ML_DSA_87), true},
		} {
			t.Run(origin.name+"/"+tc.name, func(t *testing.T) {
				err := origin.run(&nativeSuiteAvailabilityRotation{create: tc.set, spend: tc.set}, DefaultSuiteRegistry())
				if tc.pass {
					if err != nil {
						t.Fatalf("included suite: %v", err)
					}
				} else {
					mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, origin.message, TxErrorCauseUnspecified)
				}
			})
		}
	}
	for _, tc := range []struct {
		name     string
		rotation RotationProvider
		registry *SuiteRegistry
	}{
		{"both_nil", nil, nil},
		{"nil_rotation", nil, DefaultSuiteRegistry()},
		{"nil_registry", DefaultRotationProvider{}, nil},
	} {
		if err := f.origins()[1].run(tc.rotation, tc.registry); err != nil {
			t.Fatalf("%s defaults: %v", tc.name, err)
		}
	}

	sentinel := WitnessItem{SuiteID: SUITE_ID_SENTINEL}
	malformedSentinel := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: []byte{1}}
	for _, queued := range []bool{false, true} {
		for _, tc := range []struct {
			name, message string
			code          ErrorCode
			ws            []WitnessItem
			calls         int
		}{
			{"all_sentinel", "CORE_MULTISIG threshold not met", TX_ERR_SIG_INVALID, []WitnessItem{sentinel}, 1},
			{"malformed_sentinel", "SENTINEL witness must be keyless", TX_ERR_PARSE, []WitnessItem{malformedSentinel}, 1},
			{"slot_mismatch", "witness slot assignment mismatch", TX_ERR_PARSE, nil, 0},
		} {
			rotation := &nativeSuiteAvailabilityRotation{}
			check := testThresholdSigSpendCheck([][32]byte{{}}, 1, tc.ws, testSpendSigEnv{tx: f.tx, rotation: rotation, context: "CORE_MULTISIG"})
			var err error
			if queued {
				err = validateThresholdSigSpendQ(check.keys, check.threshold, check.witnesses, f.tx, 0, 100, [32]byte{}, 1, f.cache, NewSigCheckQueue(1), "CORE_MULTISIG", rotation, DefaultSuiteRegistry())
			} else {
				err = validateThresholdSigSpendAtHeight(check)
			}
			mustTxErrorCause(t, err, tc.code, tc.message, TxErrorCauseUnspecified)
			if rotation.spendCalls != tc.calls {
				t.Fatalf("queued=%v case=%s provider calls=%d", queued, tc.name, rotation.spendCalls)
			}
		}
	}
}

func TestNativeSuiteRegistryEntryUnavailable(t *testing.T) {
	f := newNativeSuiteAvailabilityFixture(t)
	emptyRegistry := NewSuiteRegistryFromParams(nil)
	for _, origin := range f.origins() {
		if origin.create {
			continue
		}
		t.Run(origin.name, func(t *testing.T) {
			message := origin.message[:len(origin.message)-len("not in native spend set")] + "not registered"
			rotation := &nativeSuiteAvailabilityRotation{spend: NewNativeSuiteSet(SUITE_ID_ML_DSA_87)}
			mustTxErrorCause(t, origin.run(rotation, emptyRegistry), TX_ERR_SIG_ALG_INVALID, message, TxErrorCauseNativeSuiteRegistryEntryUnavailable)
			if rotation.spendCalls != 1 {
				t.Fatalf("provider calls=%d", rotation.spendCalls)
			}
		})
	}
	err := f.origins()[1].run(&nativeSuiteAvailabilityRotation{spend: NewNativeSuiteSet()}, emptyRegistry)
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite not in native spend set", TxErrorCauseUnspecified)
	badLengths := f.w
	badLengths.Pubkey = badLengths.Pubkey[:1]
	err = validateP2PKSpendAtHeight(testP2PKSpendCheck(f.entry, badLengths, testSpendSigEnv{tx: f.tx, inputValue: 100, rotation: DefaultRotationProvider{}, registry: DefaultSuiteRegistry()}))
	mustTxErrorCause(t, err, TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths", TxErrorCauseUnspecified)
}

func TestNativeSuiteAvailabilityQueueRollback(t *testing.T) {
	f := newNativeSuiteAvailabilityFixture(t)
	seed := func() (*SigCheckQueue, sigCheckTask) {
		q := NewSigCheckQueue(1)
		q.Push(SUITE_ID_ML_DSA_87, f.w.Pubkey, f.w.Signature[:len(f.w.Signature)-1], [32]byte{0x61}, txerr(TX_ERR_SIG_INVALID, "seed"))
		return q, q.tasks[0]
	}
	samePrefix := func(q *SigCheckQueue, prefix sigCheckTask) bool {
		return len(q.tasks) == 1 && q.tasks[0].suiteID == prefix.suiteID && bytes.Equal(q.tasks[0].pubkey, prefix.pubkey) && bytes.Equal(q.tasks[0].sig, prefix.sig) && q.tasks[0].digest == prefix.digest && q.tasks[0].errOnFail == prefix.errOnFail
	}
	for _, tc := range []struct {
		name string
		run  func(*SigCheckQueue, RotationProvider, *SuiteRegistry) error
	}{
		{"p2pk", func(q *SigCheckQueue, r RotationProvider, reg *SuiteRegistry) error { return validateP2PKSpendQ(f.entry, f.w, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, r, reg) }},
		{"htlc", func(q *SigCheckQueue, r RotationProvider, reg *SuiteRegistry) error { return validateHTLCSpendQ(f.htlcEntry, f.path, f.w, f.tx, 0, 100, [32]byte{}, 1, 0, f.cache, q, r, reg) }},
		{"stealth", func(q *SigCheckQueue, r RotationProvider, reg *SuiteRegistry) error { return validateCoreStealthSpendQ(f.stealthEntry, f.w, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, r, reg) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, prefix := seed()
			mustTxErrorCause(t, tc.run(q, &nativeSuiteAvailabilityRotation{}, DefaultSuiteRegistry()), TX_ERR_SIG_ALG_INVALID, "CORE_"+map[string]string{"p2pk": "P2PK", "htlc": "HTLC", "stealth": "STEALTH"}[tc.name]+" suite not in native spend set", TxErrorCauseNativeSuiteSetUnavailable)
			if !samePrefix(q, prefix) {
				t.Fatalf("queue prefix changed: %+v", q.tasks)
			}
			if err := q.Flush(); err != nil {
				t.Fatalf("seed flush: %v", err)
			}
		})
	}

	q, prefix := seed()
	err := validateThresholdSigSpendQ([][32]byte{f.keyID}, 1, []WitnessItem{f.w}, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, "CORE_MULTISIG", &nativeSuiteAvailabilityRotation{}, DefaultSuiteRegistry())
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, "CORE_MULTISIG suite not in native spend set", TxErrorCauseNativeSuiteSetUnavailable)
	if !samePrefix(q, prefix) {
		t.Fatalf("threshold set rollback changed prefix: %+v", q.tasks)
	}

	q, prefix = seed()
	first := f.w
	second := f.w
	second.SuiteID = 0x02
	rotation := &nativeSuiteAvailabilityRotation{spend: NewNativeSuiteSet(SUITE_ID_ML_DSA_87, 0x02)}
	err = validateThresholdSigSpendQ([][32]byte{f.keyID, f.keyID}, 2, []WitnessItem{first, second}, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, "CORE_VAULT", rotation, DefaultSuiteRegistry())
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, "CORE_VAULT suite not registered", TxErrorCauseNativeSuiteRegistryEntryUnavailable)
	if !samePrefix(q, prefix) {
		t.Fatalf("late registry rollback changed prefix: %+v", q.tasks)
	}
	sentinel := WitnessItem{SuiteID: SUITE_ID_SENTINEL}
	if err := validateThresholdSigSpendQ([][32]byte{f.keyID, {}}, 1, []WitnessItem{first, sentinel}, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, "CORE_VAULT", nil, nil); err != nil {
		t.Fatalf("subsequent threshold validation: %v", err)
	}
	if q.Len() != 2 {
		t.Fatalf("subsequent queue length=%d", q.Len())
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("subsequent flush: %v", err)
	}
}

func TestNativeSuiteAvailabilityPublicPaths(t *testing.T) {
	f := newNativeSuiteAvailabilityFixture(t)
	createRotation := &nativeSuiteAvailabilityRotation{}
	tx := &Tx{Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: f.entry.CovenantData}}}
	mustTxErrorCause(t, ValidateTxCovenantsGenesis(tx, [32]byte{}, 1, createRotation), TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite not in native create set", TxErrorCauseNativeSuiteSetUnavailable)
	if createRotation.createCalls != 1 {
		t.Fatalf("create provider calls=%d", createRotation.createCalls)
	}
	if err := ValidateTxCovenantsGenesis(tx, [32]byte{}, 1, nil); err != nil {
		t.Fatalf("subsequent create validation: %v", err)
	}

	htlcRotation := &nativeSuiteAvailabilityRotation{}
	mustTxErrorCause(t, ValidateHTLCSpendAtHeight(f.htlcEntry, f.path, f.w, f.tx, 0, 100, [32]byte{}, 1, 0, f.cache, htlcRotation, DefaultSuiteRegistry()), TX_ERR_SIG_ALG_INVALID, "CORE_HTLC suite not in native spend set", TxErrorCauseNativeSuiteSetUnavailable)
	badPath := f.path
	badPath.SuiteID = 0x02
	err := ValidateHTLCSpendAtHeight(f.htlcEntry, badPath, f.w, f.tx, 0, 100, [32]byte{}, 1, 0, f.cache, htlcRotation, DefaultSuiteRegistry())
	mustTxErrorCause(t, err, TX_ERR_PARSE, "CORE_HTLC selector suite_id invalid", TxErrorCauseUnspecified)
	if htlcRotation.spendCalls != 1 {
		t.Fatalf("HTLC provider calls=%d", htlcRotation.spendCalls)
	}
	if err := ValidateHTLCSpendAtHeight(f.htlcEntry, f.path, f.w, f.tx, 0, 100, [32]byte{}, 1, 0, f.cache, nil, nil); err != nil {
		t.Fatalf("subsequent HTLC validation: %v", err)
	}

	prev := [32]byte{0x73}
	raw := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_P2PK, f.entry.CovenantData, []WitnessItem{f.w})
	utxos := func() map[Outpoint]UtxoEntry { return map[Outpoint]UtxoEntry{{Txid: prev, Vout: 0}: f.entry} }
	spendRotation := &nativeSuiteAvailabilityRotation{create: NewNativeSuiteSet(SUITE_ID_ML_DSA_87)}
	_, err = CheckTransactionWithOwnedUtxoSetAndSuiteContext(raw, utxos(), 1, 0, [32]byte{}, spendRotation, DefaultSuiteRegistry())
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, "CORE_P2PK suite not in native spend set", TxErrorCauseNativeSuiteSetUnavailable)
	if spendRotation.createCalls != 1 || spendRotation.spendCalls != 1 {
		t.Fatalf("transaction provider calls create=%d spend=%d", spendRotation.createCalls, spendRotation.spendCalls)
	}
	if _, err := CheckTransactionWithOwnedUtxoSetAndSuiteContext(raw, utxos(), 1, 0, [32]byte{}, nil, nil); err != nil {
		t.Fatalf("subsequent public transaction: %v", err)
	}

	results, err := RunTxValidationWorkers(context.Background(), 1, []TxValidationContext{{TxIndex: 1, Tx: f.tx, ResolvedInputs: []UtxoEntry{f.entry}, WitnessStart: 0, WitnessEnd: 1, SighashCache: f.cache}}, [32]byte{}, 1, 0, nil)
	if err != nil || len(results) != 1 || results[0].Err != nil || !results[0].Value.Valid {
		t.Fatalf("worker result=%+v err=%v", results, err)
	}
}
