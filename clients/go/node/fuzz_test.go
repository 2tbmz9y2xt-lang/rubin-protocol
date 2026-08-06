package node

import (
	"bytes"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const fuzzMaxDAPayloadLen = 2048

func fuzzSign(v int) int {
	switch {
	case v > 0:
		return 1
	case v < 0:
		return -1
	default:
		return 0
	}
}

func fuzzCompareUint64(a, b uint64) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	default:
		return 0
	}
}

// fuzzFee composes a fuzzed fee from two u64 words so the corpus reaches the
// full u128 fee domain. Drawing the fee as a single uint64 leaves the high limb
// provably zero on every input, which hides the carry and high-word limbs of
// consensus.CompareFeeRate's 192-bit cross product from the whole target.
func fuzzFee(hi, lo uint64) consensus.Uint128 {
	return consensus.Uint128{Hi: hi, Lo: lo}
}

func fuzzFeeRateOracleSign(feeA consensus.Uint128, weightA uint64, feeB consensus.Uint128, weightB uint64) int {
	if weightA == 0 || weightB == 0 {
		return 0
	}
	// math/big keeps every product bit of the u128-by-u64 cross multiplication
	// (canonical_domain permits it for exact products), so the oracle is
	// independent of the fixed-width limb arithmetic under test.
	left := new(big.Int).Mul(feeA.Big(), new(big.Int).SetUint64(weightB))
	right := new(big.Int).Mul(feeB.Big(), new(big.Int).SetUint64(weightA))
	return left.Cmp(right)
}

func fuzzEvictionPriorityOracleSign(feeA consensus.Uint128, weightA, seqA uint64, feeB consensus.Uint128, weightB, seqB uint64) int {
	if cmp := fuzzFeeRateOracleSign(feeA, weightA, feeB, weightB); cmp != 0 {
		return cmp
	}
	if cmp := feeA.Big().Cmp(feeB.Big()); cmp != 0 {
		return cmp
	}
	return fuzzCompareUint64(seqA, seqB)
}

func fuzzTxid(seed byte, fallback byte) [32]byte {
	if seed == 0 {
		seed = fallback
	}
	var txid [32]byte
	txid[0] = seed
	return txid
}

func fuzzCheckedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}

func fuzzCheckedAdd(a, b uint64) (uint64, bool) {
	if b > ^uint64(0)-a {
		return 0, false
	}
	return a + b, true
}

// Target: Mempool.AddTx capacity ordering via compareFeeRateWeightValues and
// compareMempoolEvictionPriority.
// Invariant: checked fee/weight cross multiplication is deterministic, ordered
// by fee/weight then absolute fee then admission sequence, and source metadata
// grants no ordering priority.
// Public/runtime entrypoint: AddTx/AddRemoteTx/AddReorgTx -> addEntryLocked ->
// validateCapacityAdmissionLocked -> capacityEvictionPlanLocked.
// Early guards: zero weights are invalid resident/candidate metadata in the
// runtime eviction path; the property asserts the helper's fail-closed neutral
// result for zero-weight inputs and then stops that row.
// Direct assertion: helper signs must match a big.Int oracle and source variants
// must produce identical priority comparisons.
// Domain: each fee is drawn as two u64 words so the corpus covers the whole
// u128 fee domain (RUB-1127) and the cross product exercises all 192 bits;
// weights stay u64 per canonical_domain.
func FuzzMempoolFeeWeightOrdering(f *testing.F) {
	f.Add(uint64(0), uint64(3), uint64(2), uint64(0), uint64(5), uint64(3), uint64(1), uint64(2), byte(1), byte(2))
	f.Add(uint64(0), uint64(4), uint64(2), uint64(0), uint64(9), uint64(3), uint64(7), uint64(6), byte(3), byte(4))
	f.Add(uint64(0), ^uint64(0), ^uint64(0)-1, uint64(0), ^uint64(0)-2, ^uint64(0)-3, uint64(11), uint64(12), byte(5), byte(6))
	// High-word limb: feeA*weightB is exactly 2^128, so a cross product that
	// drops the high 64 bits of the 192-bit result reads it as 0 and reverses
	// the verdict against feeB*weightA = 1.
	f.Add(uint64(1)<<32, uint64(0), uint64(1), uint64(0), uint64(1), uint64(1)<<32, uint64(3), uint64(4), byte(7), byte(8))
	// Carry limb: feeA*weightB carries out of the middle word into bit 128,
	// and feeB*weightA = 5*2^127 sits strictly between the correct product and
	// the product a dropped carry would produce.
	f.Add(uint64(2), ^uint64(0), uint64(4), uint64(5)<<61, uint64(0), ^uint64(0), uint64(5), uint64(6), byte(9), byte(10))
	f.Fuzz(func(t *testing.T, feeAHi, feeALo, weightA, feeBHi, feeBLo, weightB, seqA, seqB uint64, seedA, seedB byte) {
		feeA := fuzzFee(feeAHi, feeALo)
		feeB := fuzzFee(feeBHi, feeBLo)
		gotRate := fuzzSign(compareFeeRateWeightValues(feeA, weightA, feeB, weightB))
		wantRate := fuzzFeeRateOracleSign(feeA, weightA, feeB, weightB)
		if gotRate != wantRate {
			t.Fatalf("fee/weight compare sign=%d, want %d (feeA=%s weightA=%d feeB=%s weightB=%d)", gotRate, wantRate, feeA.String(), weightA, feeB.String(), weightB)
		}
		gotReverse := fuzzSign(compareFeeRateWeightValues(feeB, weightB, feeA, weightA))
		if gotReverse != -wantRate {
			t.Fatalf("reverse fee/weight compare sign=%d, want %d", gotReverse, -wantRate)
		}
		if weightA == 0 || weightB == 0 {
			return
		}

		entryA := &mempoolEntry{txid: fuzzTxid(seedA, 0xa1), fee: feeA, weight: weightA, admissionSeq: seqA, source: mempoolTxSourceLocal}
		entryB := &mempoolEntry{txid: fuzzTxid(seedB, 0xb2), fee: feeB, weight: weightB, admissionSeq: seqB, source: mempoolTxSourceRemote}
		gotPriority := fuzzSign(compareMempoolEvictionPriority(mempoolEvictionPlanEntry{entry: entryA}, mempoolEvictionPlanEntry{entry: entryB}))
		wantPriority := fuzzEvictionPriorityOracleSign(feeA, weightA, seqA, feeB, weightB, seqB)
		if gotPriority != wantPriority {
			t.Fatalf("eviction priority sign=%d, want %d (feeA=%s weightA=%d seqA=%d feeB=%s weightB=%d seqB=%d)", gotPriority, wantPriority, feeA.String(), weightA, seqA, feeB.String(), weightB, seqB)
		}
		gotWorse := evictionPlanEntryWorse(mempoolEvictionPlanEntry{entry: entryA}, mempoolEvictionPlanEntry{entry: entryB})
		wantWorse := gotPriority < 0 || (gotPriority == 0 && bytes.Compare(entryA.txid[:], entryB.txid[:]) > 0)
		if gotWorse != wantWorse {
			t.Fatalf("evictionPlanEntryWorse=%v, want %v (priority=%d txidA=%x txidB=%x)", gotWorse, wantWorse, gotPriority, entryA.txid, entryB.txid)
		}

		residentSeq := seqA
		if residentSeq == 0 {
			residentSeq = 1
		}
		resident := &mempoolEntry{txid: fuzzTxid(seedA, 0xc3), fee: feeA, weight: weightA, admissionSeq: residentSeq, source: mempoolTxSourceRemote}
		candidate := &mempoolEntry{txid: fuzzTxid(seedB, 0xd4), fee: feeA, weight: weightA, source: mempoolTxSourceLocal}
		gotCandidateTie := fuzzSign(compareMempoolEvictionPriority(mempoolEvictionPlanEntry{entry: candidate, candidate: true}, mempoolEvictionPlanEntry{entry: resident}))
		if gotCandidateTie != -1 {
			t.Fatalf("candidate exact tie priority=%d, want -1 to preserve no-RBF capacity behavior", gotCandidateTie)
		}

		entryA.source = mempoolTxSourceReorg
		entryB.source = mempoolTxSourceLocal
		gotWithSources := fuzzSign(compareMempoolEvictionPriority(mempoolEvictionPlanEntry{entry: entryA}, mempoolEvictionPlanEntry{entry: entryB}))
		if gotWithSources != gotPriority {
			t.Fatalf("source metadata changed eviction priority: got %d after %d", gotWithSources, gotPriority)
		}
	})
}

// Target: Mempool.AddTx rolling-floor admission via feeRateBelowFloor,
// entryFloorRate, and saturatingAddMinRelayFeeStep.
// Invariant: local rolling floor clamps to DefaultMempoolMinFeeRate, overflow
// rejects fail-closed, non-divisible evicted rates use floor division, and
// min-fee-step addition saturates.
// Public/runtime entrypoint: AddTx/AddRemoteTx/AddReorgTx -> addEntryLocked ->
// validateFeeFloorLockedWithFloor; eviction raise uses raiseMinFeeRateAfterEvictionLocked.
// Early guards: zero transaction weight is invalid policy metadata and must be
// treated as below-floor without division.
// Direct assertion: feeRateBelowFloor and entryFloorRate must match checked
// arithmetic oracles, including tightness around returned floors.
func FuzzMempoolRollingFloorBoundaries(f *testing.F) {
	f.Add(uint64(3), uint64(2), uint64(0))
	f.Add(uint64(5), uint64(3), uint64(1))
	f.Add(uint64(9), uint64(3), uint64(3))
	f.Add(uint64(^uint64(0)), uint64(^uint64(0)), uint64(^uint64(0)))
	f.Fuzz(func(t *testing.T, fee, weight, floor uint64) {
		effectiveFloor := floor
		if effectiveFloor < DefaultMempoolMinFeeRate {
			effectiveFloor = DefaultMempoolMinFeeRate
		}
		product, productOK := fuzzCheckedMul(weight, effectiveFloor)
		wantBelow := weight == 0 || !productOK || fee < product
		if gotBelow := feeRateBelowFloor(consensus.Uint128FromU64(fee), weight, floor); gotBelow != wantBelow {
			t.Fatalf("feeRateBelowFloor=%v, want %v (fee=%d weight=%d floor=%d effective=%d)", gotBelow, wantBelow, fee, weight, floor, effectiveFloor)
		}

		entry := &mempoolEntry{fee: consensus.Uint128FromU64(fee), weight: weight}
		entryFloor, ok := entryFloorRate(entry)
		if weight == 0 {
			if ok || entryFloor != 0 {
				t.Fatalf("entryFloorRate zero-weight = (%d,%v), want (0,false)", entryFloor, ok)
			}
			return
		}
		if !ok || entryFloor != fee/weight {
			t.Fatalf("entryFloorRate=(%d,%v), want (%d,true)", entryFloor, ok, fee/weight)
		}
		if entryFloor >= DefaultMempoolMinFeeRate && feeRateBelowFloor(consensus.Uint128FromU64(fee), weight, entryFloor) {
			t.Fatalf("entry should satisfy its returned floor (fee=%d weight=%d floor=%d)", fee, weight, entryFloor)
		}
		if entryFloor != ^uint64(0) && !feeRateBelowFloor(consensus.Uint128FromU64(fee), weight, entryFloor+1) {
			t.Fatalf("entry floor is not tight (fee=%d weight=%d floor=%d)", fee, weight, entryFloor)
		}
		wantRaised := ^uint64(0)
		if entryFloor <= ^uint64(0)-DefaultMempoolMinFeeRate {
			wantRaised = entryFloor + DefaultMempoolMinFeeRate
		}
		if gotRaised := saturatingAddMinRelayFeeStep(entryFloor); gotRaised != wantRaised {
			t.Fatalf("saturatingAddMinRelayFeeStep=%d, want %d", gotRaised, wantRaised)
		}
	})
}

func fuzzCanonicalPolicyFee(fee uint64) uint64 {
	// A checked non-coinbase spend needs at least one positive output, so the
	// maximum fuzzed fee is normalized to the highest representable fee with a
	// one-unit output.
	if fee == ^uint64(0) {
		return ^uint64(0) - 1
	}
	return fee
}

func fuzzCloneUtxos(utxos map[consensus.Outpoint]consensus.UtxoEntry) map[consensus.Outpoint]consensus.UtxoEntry {
	clone := make(map[consensus.Outpoint]consensus.UtxoEntry, len(utxos))
	for outpoint, entry := range utxos {
		entry.CovenantData = append([]byte(nil), entry.CovenantData...)
		clone[outpoint] = entry
	}
	return clone
}

type fuzzLockedSigner struct {
	mu sync.Mutex
	kp *consensus.MLDSA87Keypair
}

func (s *fuzzLockedSigner) PubkeyBytes() []byte {
	return s.kp.PubkeyBytes()
}

func (s *fuzzLockedSigner) SignDigest32(digest [32]byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kp.SignDigest32(digest)
}

func fuzzCheckedDaPolicyTx(
	t *testing.T,
	daTx bool,
	payloadLen int,
	fee uint64,
	signer consensus.DigestSigner,
	address []byte,
) (*consensus.CheckedTransaction, map[consensus.Outpoint]consensus.UtxoEntry) {
	t.Helper()
	policyFee := fuzzCanonicalPolicyFee(fee)
	state, outpoints := testSpendableChainState(address, []uint64{policyFee + 1})
	utxos := fuzzCloneUtxos(state.Utxos)

	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []consensus.TxInput{{
			PrevTxid: outpoints[0].Txid,
			PrevVout: outpoints[0].Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{{
			Value:        1,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), address...),
		}},
		Locktime: 0,
	}
	if daTx {
		if payloadLen <= 0 {
			payloadLen = 1
		}
		tx.TxKind = 0x01
		tx.DaPayload = make([]byte, payloadLen)
		for i := range tx.DaPayload {
			tx.DaPayload[i] = byte(i)
		}
		tx.DaCommitCore = &consensus.DaCommitCore{
			ChunkCount:  1,
			BatchNumber: 1,
		}
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(signed fuzz tx): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(signed fuzz tx): %v", err)
	}

	tx, txid, wtxid, consumed, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx(signed fuzz tx): %v", err)
	}
	if consumed != len(txBytes) {
		t.Fatalf("ParseTx consumed=%d, want %d", consumed, len(txBytes))
	}
	checked, err := consensus.CheckParsedTransactionWithOwnedUtxoSetAndSuiteContext(
		txBytes,
		tx,
		consensus.ParsedTxIDs{TxID: txid, WTxID: wtxid},
		fuzzCloneUtxos(utxos),
		101,
		0,
		devnetGenesisChainID,
		consensus.SuiteValidationContext{},
	)
	if err != nil {
		t.Fatalf("CheckParsedTransactionWithOwnedUtxoSetAndSuiteContext(signed fuzz tx): %v", err)
	}
	if checked.Fee.Cmp(consensus.Uint128FromU64(policyFee)) != 0 {
		t.Fatalf("checked fee=%d, want %d", checked.Fee, policyFee)
	}
	return checked, utxos
}

// Target: Mempool.AddTx and RelayMetadata DA Stage C policy via
// RejectDaAnchorTxPolicy.
// Invariant: DA required fee uses checked arithmetic and required_fee =
// max(relay_fee_floor, da_fee_floor + da_surcharge), while non-DA transactions
// short-circuit the policy helper before fee/UTXO access after the shared
// checked transaction path has accepted the tx.
// Public/runtime entrypoint: Mempool.AddTx/RelayMetadata parse and check a
// signed transaction, then applyPolicyAgainstState calls RejectDaAnchorTxPolicy
// for DA policy classification.
// Early guards: the fuzz target constructs a signed P2PK spend with matching
// covenant data, witness, and UTXO, then marshals, parses, and runs the shared
// checked transaction path before calling the policy oracle; payload length is
// bounded to keep fuzz smoke stable.
// Direct assertion: reject/admit, daBytes, overflow reason class, exact-boundary
// acceptance, and floor-1 rejection must match an independent checked oracle.
func FuzzDaFeeFloorPolicyBoundaries(f *testing.F) {
	f.Add(uint16(10), uint64(2000), uint64(0), uint64(200), uint64(0), true)
	f.Add(uint16(10), uint64(1999), uint64(0), uint64(200), uint64(0), true)
	f.Add(uint16(10), uint64(3383), uint64(1), uint64(1), uint64(0), true)
	f.Add(uint16(10), uint64(^uint64(0)), uint64(^uint64(0)), uint64(1), uint64(0), true)
	f.Add(uint16(0), uint64(0), uint64(^uint64(0)), uint64(^uint64(0)), uint64(^uint64(0)), false)
	signer, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			f.Skipf("ML-DSA backend unavailable: %v", err)
		}
		f.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	f.Cleanup(func() { signer.Close() })
	lockedSigner := &fuzzLockedSigner{kp: signer}
	address := consensus.P2PKCovenantDataForPubkey(lockedSigner.PubkeyBytes())

	f.Fuzz(func(t *testing.T, payloadSeed uint16, fee, currentMinFeeRate, minDaFeeRate, daSurchargePerByte uint64, daTx bool) {
		payloadLen := int(payloadSeed % fuzzMaxDAPayloadLen)
		if daTx && payloadLen == 0 {
			payloadLen = 1
		}
		checked, utxos := fuzzCheckedDaPolicyTx(t, daTx, payloadLen, fee, lockedSigner, address)
		weight := checked.Weight
		wantDaBytes := checked.DaBytes
		policyFee := checked.Fee
		if daTx && wantDaBytes != uint64(payloadLen) {
			t.Fatalf("DA tx daBytes=%d, want payloadLen=%d before policy oracle", wantDaBytes, payloadLen)
		}
		if !daTx && wantDaBytes != 0 {
			t.Fatalf("non-DA tx daBytes=%d, want 0 before policy oracle", wantDaBytes)
		}
		policyUtxos := utxos
		if wantDaBytes == 0 {
			policyUtxos = nil
		}

		reject, gotDaBytes, reason, policyErr := RejectDaAnchorTxPolicy(checked.Tx, policyUtxos, currentMinFeeRate, minDaFeeRate, daSurchargePerByte)
		if gotDaBytes != wantDaBytes {
			t.Fatalf("daBytes=%d, want %d", gotDaBytes, wantDaBytes)
		}
		if wantDaBytes == 0 {
			if reject || reason != "" || policyErr != nil {
				t.Fatalf("non-DA tx should short-circuit policy, got reject=%v reason=%q err=%v", reject, reason, policyErr)
			}
			return
		}

		// RUB-1127: the relay-floor term is the exact 128-bit weight*rate
		// product and has no overflow branch, so the oracle never expects a
		// product-overflow rejection here. The DA-side terms below keep their
		// u64 overflow expectations.
		relayFloor := mulU64Exact(weight, currentMinFeeRate)
		daFloor, ok := fuzzCheckedMul(wantDaBytes, minDaFeeRate)
		if !ok {
			if !reject || policyErr == nil || !strings.Contains(reason, "DA fee floor overflow") {
				t.Fatalf("DA floor overflow got reject=%v reason=%q err=%v", reject, reason, policyErr)
			}
			return
		}
		daSurcharge, ok := fuzzCheckedMul(wantDaBytes, daSurchargePerByte)
		if !ok {
			if !reject || policyErr == nil || !strings.Contains(reason, "DA surcharge overflow") {
				t.Fatalf("DA surcharge overflow got reject=%v reason=%q err=%v", reject, reason, policyErr)
			}
			return
		}
		daRequired, ok := fuzzCheckedAdd(daFloor, daSurcharge)
		if !ok {
			if !reject || policyErr == nil || !strings.Contains(reason, "DA required fee overflow") {
				t.Fatalf("DA required overflow got reject=%v reason=%q err=%v", reject, reason, policyErr)
			}
			return
		}
		required := relayFloor
		if widened := consensus.Uint128FromU64(daRequired); widened.Cmp(required) > 0 {
			required = widened
		}
		wantReject := !required.IsZero() && policyFee.Cmp(required) < 0
		if reject != wantReject {
			t.Fatalf("reject=%v, want %v (fee=%s required=%s relay=%s da=%d surcharge=%d weight=%d daBytes=%d)", reject, wantReject, policyFee.String(), required.String(), relayFloor.String(), daFloor, daSurcharge, weight, wantDaBytes)
		}
		if wantReject {
			if policyErr != nil || !strings.Contains(reason, "DA fee below Stage C floor") {
				t.Fatalf("below-floor reject reason=%q err=%v", reason, policyErr)
			}
			return
		}
		if reason != "" || policyErr != nil {
			t.Fatalf("accepted DA tx should not carry reason/err, reason=%q err=%v", reason, policyErr)
		}
	})
}
