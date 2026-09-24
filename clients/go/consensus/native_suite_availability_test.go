package consensus

import (
	"bytes"
	"context"
	"errors"
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
	tx.TxNonce, tx.Outputs[0] = 1, TxOutput{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: bytes.Clone(entry.CovenantData)}
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
	for _, origin := range f.origins() {
		mustTxErrorCause(t, origin.run(typedNil, DefaultSuiteRegistry()), TX_ERR_SIG_ALG_INVALID, origin.message, TxErrorCauseNativeSuiteSetUnavailable)
	}
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
	for _, origin := range f.origins() {
		if origin.create {
			continue
		}
		err := origin.run(&nativeSuiteAvailabilityRotation{spend: NewNativeSuiteSet()}, emptyRegistry)
		mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, origin.message, TxErrorCauseUnspecified)
	}
	bad := f
	bad.w.Signature = []byte{SIGHASH_ALL}
	for _, origin := range bad.origins() {
		if origin.create {
			continue
		}
		err := origin.run(DefaultRotationProvider{}, DefaultSuiteRegistry())
		mustTxErrorCause(t, err, TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths", TxErrorCauseUnspecified)
	}
}

func TestNativeSuiteAvailabilityQueueRollback(t *testing.T) {
	f := newNativeSuiteAvailabilityFixture(t)
	seed := func() (*SigCheckQueue, sigCheckTask) {
		q := NewSigCheckQueue(1)
		q.Push(SUITE_ID_ML_DSA_87, f.w.Pubkey, f.w.Signature[:len(f.w.Signature)-1], [32]byte{0x61}, txerr(TX_ERR_SIG_INVALID, "seed"))
		prefix := q.tasks[0]
		prefix.pubkey, prefix.sig = bytes.Clone(prefix.pubkey), bytes.Clone(prefix.sig)
		return q, prefix
	}
	samePrefix := func(q *SigCheckQueue, prefix sigCheckTask) bool {
		if len(q.tasks) != 1 {
			return false
		}
		typedError, ok := q.tasks[0].errOnFail.(*TxError)
		return ok && q.tasks[0].suiteID == prefix.suiteID && bytes.Equal(q.tasks[0].pubkey, prefix.pubkey) && bytes.Equal(q.tasks[0].sig, prefix.sig) && q.tasks[0].digest == prefix.digest && errors.Is(typedError, prefix.errOnFail)
	}
	for _, tc := range []struct {
		name string
		run  func(*SigCheckQueue, RotationProvider, *SuiteRegistry) error
	}{
		{"p2pk", func(q *SigCheckQueue, r RotationProvider, reg *SuiteRegistry) error {
			return validateP2PKSpendQ(f.entry, f.w, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, r, reg)
		}},
		{"htlc", func(q *SigCheckQueue, r RotationProvider, reg *SuiteRegistry) error {
			return validateHTLCSpendQ(f.htlcEntry, f.path, f.w, f.tx, 0, 100, [32]byte{}, 1, 0, f.cache, q, r, reg)
		}},
		{"stealth", func(q *SigCheckQueue, r RotationProvider, reg *SuiteRegistry) error {
			return validateCoreStealthSpendQ(f.stealthEntry, f.w, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, r, reg)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, missingRegistry := range []bool{false, true} {
				q, prefix := seed()
				rotation := &nativeSuiteAvailabilityRotation{}
				registry, suffix, cause := DefaultSuiteRegistry(), "not in native spend set", TxErrorCauseNativeSuiteSetUnavailable
				if missingRegistry {
					rotation.spend, registry, suffix, cause = NewNativeSuiteSet(SUITE_ID_ML_DSA_87), NewSuiteRegistryFromParams(nil), "not registered", TxErrorCauseNativeSuiteRegistryEntryUnavailable
				}
				message := "CORE_" + map[string]string{"p2pk": "P2PK", "htlc": "HTLC", "stealth": "STEALTH"}[tc.name] + " suite " + suffix
				mustTxErrorCause(t, tc.run(q, rotation, registry), TX_ERR_SIG_ALG_INVALID, message, cause)
				if !samePrefix(q, prefix) {
					t.Fatalf("queue prefix changed: %+v", q.tasks)
				}
				if err := tc.run(q, nil, nil); err != nil || q.Len() != 2 {
					t.Fatalf("subsequent validation err=%v queue=%d", err, q.Len())
				}
				if err := q.Flush(); err != nil {
					t.Fatalf("subsequent flush: %v", err)
				}
			}
		})
	}
	nextThreshold := func(q *SigCheckQueue, context string) {
		if err := validateThresholdSigSpendQ([][32]byte{f.keyID}, 1, []WitnessItem{f.w}, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, context, nil, nil); err != nil || q.Len() != 2 {
			t.Fatalf("subsequent threshold err=%v queue=%d", err, q.Len())
		}
		if err := q.Flush(); err != nil {
			t.Fatalf("subsequent threshold flush: %v", err)
		}
	}

	q, prefix := seed()
	err := validateThresholdSigSpendQ([][32]byte{f.keyID}, 1, []WitnessItem{f.w}, f.tx, 0, 100, [32]byte{}, 1, f.cache, q, "CORE_MULTISIG", &nativeSuiteAvailabilityRotation{}, DefaultSuiteRegistry())
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, "CORE_MULTISIG suite not in native spend set", TxErrorCauseNativeSuiteSetUnavailable)
	if !samePrefix(q, prefix) {
		t.Fatalf("threshold set rollback changed prefix: %+v", q.tasks)
	}
	nextThreshold(q, "CORE_MULTISIG")

	q, prefix = seed()
	secondPub := bytes.Clone(f.w.Pubkey)
	secondPub[0] ^= 1
	firstKey, secondKey := sortKeys32(f.keyID, sha3_256(secondPub))
	first, second := f.w, f.w
	if firstKey == f.keyID {
		second.Pubkey = secondPub
	} else {
		first.Pubkey = secondPub
	}
	first.SuiteID, second.SuiteID = SUITE_ID_ML_DSA_87, 0x02
	thresholdTx := *f.tx
	thresholdTx.Witness = []WitnessItem{first, second}
	thresholdCache, cacheErr := NewSighashV1PrehashCache(&thresholdTx)
	if cacheErr != nil {
		t.Fatalf("threshold cache: %v", cacheErr)
	}
	rotation := &nativeSuiteAvailabilityRotation{spend: NewNativeSuiteSet(SUITE_ID_ML_DSA_87, 0x02)}
	err = validateThresholdSigSpendQ([][32]byte{firstKey, secondKey}, 2, []WitnessItem{first, second}, &thresholdTx, 0, 100, [32]byte{}, 1, thresholdCache, q, "CORE_VAULT", rotation, DefaultSuiteRegistry())
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, "CORE_VAULT suite not registered", TxErrorCauseNativeSuiteRegistryEntryUnavailable)
	if !samePrefix(q, prefix) {
		t.Fatalf("late registry rollback changed prefix: %+v", q.tasks)
	}
	nextThreshold(q, "CORE_VAULT")
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
	htlcEarlier := func(queued bool, entry UtxoEntry, path WitnessItem, height, mtp uint64) func(RotationProvider) error {
		return func(rotation RotationProvider) error {
			if queued {
				return validateHTLCSpendQ(entry, path, f.w, f.tx, 0, 100, [32]byte{}, height, mtp, f.cache, NewSigCheckQueue(1), rotation, DefaultSuiteRegistry())
			}
			return ValidateHTLCSpendAtHeight(entry, path, f.w, f.tx, 0, 100, [32]byte{}, height, mtp, f.cache, rotation, DefaultSuiteRegistry())
		}
	}
	otherKey, wrongKey := [32]byte{0x71}, [32]byte{0x99}
	claimPreimage, wrongClaimPreimage := []byte("0123456789abcdef"), []byte("fedcba9876543210")
	wrongPreimage := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: f.keyID[:], Signature: encodeHTLCClaimPayload(wrongClaimPreimage)}
	claimKeyMismatch := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: wrongKey[:], Signature: encodeHTLCClaimPayload(claimPreimage)}
	refundKeyMismatch := WitnessItem{SuiteID: SUITE_ID_SENTINEL, Pubkey: wrongKey[:], Signature: []byte{0x01}}
	claimKeyEntry := makeHTLCEntry(sha3_256(claimPreimage), LOCK_MODE_HEIGHT, 1, f.keyID, otherKey)
	timestampEntry := makeHTLCEntry([32]byte{0x72}, LOCK_MODE_TIMESTAMP, 1, otherKey, f.keyID)
	for _, queued := range []bool{false, true} {
		for _, tc := range []struct {
			name, message string
			code          ErrorCode
			run           func(RotationProvider) error
		}{
			{"htlc_shape", "CORE_HTLC covenant_data length mismatch", TX_ERR_COVENANT_TYPE_INVALID, htlcEarlier(queued, UtxoEntry{CovenantType: COV_TYPE_HTLC}, f.path, 1, 0)},
			{"wrong_preimage", "CORE_HTLC claim preimage hash mismatch", TX_ERR_SIG_INVALID, htlcEarlier(queued, claimKeyEntry, wrongPreimage, 1, 0)},
			{"height_lock", "CORE_HTLC height lock not met", TX_ERR_TIMELOCK_NOT_MET, htlcEarlier(queued, f.htlcEntry, f.path, 0, 0)},
			{"timestamp_lock", "CORE_HTLC timestamp lock not met", TX_ERR_TIMELOCK_NOT_MET, htlcEarlier(queued, timestampEntry, f.path, 1, 0)},
			{"claim_key", "CORE_HTLC claim key_id mismatch", TX_ERR_SIG_INVALID, htlcEarlier(queued, claimKeyEntry, claimKeyMismatch, 1, 0)},
			{"refund_key", "CORE_HTLC refund key_id mismatch", TX_ERR_SIG_INVALID, htlcEarlier(queued, f.htlcEntry, refundKeyMismatch, 1, 0)},
		} {
			rotation := &nativeSuiteAvailabilityRotation{}
			mustTxErrorCause(t, tc.run(rotation), tc.code, tc.message, TxErrorCauseUnspecified)
			if rotation.spendCalls != 0 {
				t.Fatalf("queued=%v case=%s provider calls=%d", queued, tc.name, rotation.spendCalls)
			}
		}
	}
	for _, tc := range []struct {
		name, message string
		run           func(RotationProvider) error
	}{
		{"create_value", "CORE_P2PK value must be > 0", func(rotation RotationProvider) error {
			return ValidateTxCovenantsGenesis(&Tx{Outputs: []TxOutput{{CovenantType: COV_TYPE_P2PK, CovenantData: f.entry.CovenantData}}}, [32]byte{}, 1, rotation)
		}},
		{"create_shape", "invalid CORE_P2PK covenant_data length", func(rotation RotationProvider) error {
			return ValidateTxCovenantsGenesis(&Tx{Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK}}}, [32]byte{}, 1, rotation)
		}},
		{"stealth_shape", "CORE_STEALTH covenant_data length mismatch", func(rotation RotationProvider) error {
			return validateCoreStealthSpendAtHeight(coreStealthSpendValidation{entry: UtxoEntry{CovenantType: COV_TYPE_CORE_STEALTH}, w: f.w, rotation: rotation, registry: DefaultSuiteRegistry()})
		}},
		{"stealth_q_shape", "CORE_STEALTH covenant_data length mismatch", func(rotation RotationProvider) error {
			return validateCoreStealthSpendQ(UtxoEntry{CovenantType: COV_TYPE_CORE_STEALTH}, f.w, f.tx, 0, 100, [32]byte{}, 1, f.cache, NewSigCheckQueue(1), rotation, DefaultSuiteRegistry())
		}},
	} {
		rotation := &nativeSuiteAvailabilityRotation{}
		mustTxErrorCause(t, tc.run(rotation), TX_ERR_COVENANT_TYPE_INVALID, tc.message, TxErrorCauseUnspecified)
		if rotation.createCalls != 0 || rotation.spendCalls != 0 {
			t.Fatalf("case=%s provider calls=%d/%d", tc.name, rotation.createCalls, rotation.spendCalls)
		}
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

	parsed, txid := mustParseTxForUtxo(t, raw)
	workerContext, err := precomputeTxContext(1, parsed, txid, utxos(), 1)
	if err != nil {
		t.Fatalf("precomputeTxContext: %v", err)
	}
	results, err := RunTxValidationWorkers(context.Background(), 1, []TxValidationContext{workerContext}, [32]byte{}, 1, 0, nil)
	if err != nil || len(results) != 1 || results[0].Err != nil || !results[0].Value.Valid {
		t.Fatalf("worker result=%+v err=%v", results, err)
	}
}
