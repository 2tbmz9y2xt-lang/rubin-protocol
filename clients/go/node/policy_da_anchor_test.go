package node

import (
	"fmt"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// daTestTx builds a DA-bearing tx whose unique input points at prev[0]=marker
// and whose payload is exactly daPayloadBytes bytes. The output value is
// inValue - feePaid so that fee(tx) == feePaid.
func daTestTx(t *testing.T, marker byte, inValue uint64, feePaid uint64, daPayloadBytes int) (*consensus.Tx, map[consensus.Outpoint]consensus.UtxoEntry, uint64) {
	t.Helper()
	var prev [32]byte
	prev[0] = marker
	op := consensus.Outpoint{Txid: prev, Vout: 0}
	utxos := map[consensus.Outpoint]consensus.UtxoEntry{op: {Value: inValue}}
	if feePaid > inValue {
		t.Fatalf("test setup: feePaid=%d > inValue=%d", feePaid, inValue)
	}
	payload := make([]byte, daPayloadBytes)
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: 1,
		Inputs:  []consensus.TxInput{{PrevTxid: prev, PrevVout: 0}},
		Outputs: []consensus.TxOutput{{
			Value:        inValue - feePaid,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: make([]byte, consensus.MAX_P2PK_COVENANT_DATA),
		}},
		DaPayload: payload,
		DaCommitCore: &consensus.DaCommitCore{
			ChunkCount:  1,
			BatchNumber: 1,
		},
	}
	tx.Outputs[0].CovenantData[0] = consensus.SUITE_ID_ML_DSA_87
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	return tx, utxos, weight
}

func nonDaTestTx(t *testing.T, marker byte, inValue uint64, feePaid uint64) (*consensus.Tx, map[consensus.Outpoint]consensus.UtxoEntry, uint64) {
	t.Helper()
	if feePaid > inValue {
		t.Fatalf("test setup: feePaid=%d > inValue=%d", feePaid, inValue)
	}
	var prev [32]byte
	prev[0] = marker
	op := consensus.Outpoint{Txid: prev, Vout: 0}
	utxos := map[consensus.Outpoint]consensus.UtxoEntry{op: {Value: inValue}}
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []consensus.TxInput{{PrevTxid: prev, PrevVout: 0}},
		Outputs: []consensus.TxOutput{{
			Value:        inValue - feePaid,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: make([]byte, consensus.MAX_P2PK_COVENANT_DATA),
		}},
	}
	tx.Outputs[0].CovenantData[0] = consensus.SUITE_ID_ML_DSA_87
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	return tx, utxos, weight
}

func wantStageCFloorReason(fee, requiredFee, relayFloor, daFloor, daSurcharge, weight, daPayloadLen uint64) string {
	return fmt.Sprintf("DA fee below Stage C floor (fee=%d required_fee=%d relay_fee_floor=%d da_fee_floor=%d da_surcharge=%d weight=%d da_payload_len=%d)",
		fee, requiredFee, relayFloor, daFloor, daSurcharge, weight, daPayloadLen)
}

// Hostile matrix #1 + matrix R2#2 + accepted_cases p3:
// PolicyDaSurchargePerByte=0 must NOT bypass min_da_fee_rate.
// Disable the relay floor so the test is fail-sensitive to da_fee_floor
// itself, not to max(relay_fee_floor, da_required_fee) selecting relay.
func TestRejectDaAnchorTxPolicy_ZeroSurchargeStillEnforcesDaFloor(t *testing.T) {
	tx, utxos, weight := daTestTx(t, 0x10, 100, 0 /* fee */, 10 /* da bytes */)
	const currentMin = uint64(0)
	const minDaFee = uint64(1)
	const surcharge = uint64(0)
	reject, daBytes, reason, err := RejectDaAnchorTxPolicy(tx, utxos, currentMin, minDaFee, surcharge)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if daBytes != 10 {
		t.Fatalf("daBytes=%d want=10", daBytes)
	}
	if !reject {
		t.Fatalf("expected reject: zero surcharge must not bypass DA floor; reason=%q", reason)
	}
	wantReason := wantStageCFloorReason(0, 10, 0, 10, 0, weight, 10)
	if reason != wantReason {
		t.Fatalf("reason=%q, want exact %q", reason, wantReason)
	}
}

// accepted_cases p4: min_da_fee_rate=0 still enforces surcharge when
// PolicyDaSurchargePerByte > 0.
// Disable the relay floor so the reject proof is fail-sensitive to
// da_surcharge itself.
func TestRejectDaAnchorTxPolicy_ZeroMinDaFeeRateStillEnforcesSurcharge(t *testing.T) {
	tx, utxos, weight := daTestTx(t, 0x11, 100, 5 /* fee */, 10 /* da bytes */)
	const currentMin = uint64(0)
	const minDaFee = uint64(0)
	const surcharge = uint64(2) // da_required = 10 * 2 = 20; fee=5 < 20 → reject
	reject, daBytes, reason, err := RejectDaAnchorTxPolicy(tx, utxos, currentMin, minDaFee, surcharge)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if daBytes != 10 {
		t.Fatalf("daBytes=%d want=10", daBytes)
	}
	if !reject {
		t.Fatalf("expected reject: surcharge floor not satisfied; reason=%q", reason)
	}
	wantReason := wantStageCFloorReason(5, 20, 0, 0, 20, weight, 10)
	if reason != wantReason {
		t.Fatalf("reason=%q, want exact %q", reason, wantReason)
	}
}

// Hostile matrix DA-floor dominance + relay-floor dominance.
func TestRejectDaAnchorTxPolicy_RelayFloorDominanceSelectsRelay(t *testing.T) {
	// Build DA tx with large weight (long payload bytes drive weight up
	// well above da_payload_len). currentMin=10 -> relay_floor = weight*10.
	// min_da_fee_rate=1, surcharge=0 -> da_required = da_payload_len.
	// With weight >> da_payload_len, relay_floor > da_required.
	tx, utxos, weight := daTestTx(t, 0x12, 1<<32, 1 /* underpaid */, 10)
	const currentMin = uint64(10)
	const minDaFee = uint64(1)
	const surcharge = uint64(0)
	reject, daBytes, reason, err := RejectDaAnchorTxPolicy(tx, utxos, currentMin, minDaFee, surcharge)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if daBytes != 10 {
		t.Fatalf("daBytes=%d want=10", daBytes)
	}
	if !reject {
		t.Fatalf("expected reject: fee below relay floor; reason=%q", reason)
	}
	relayFloor := weight * currentMin
	daFloor := uint64(10) * minDaFee
	daSurcharge := uint64(10) * surcharge
	wantReason := wantStageCFloorReason(1, relayFloor, relayFloor, daFloor, daSurcharge, weight, 10)
	if reason != wantReason {
		t.Fatalf("reason=%q, want exact %q", reason, wantReason)
	}
}

func TestRejectDaAnchorTxPolicy_DaFloorDominanceSelectsDa(t *testing.T) {
	// Big payload, small weight: choose currentMin=1, minDaFee=1000,
	// surcharge=0. Payload=10 -> da_required=10000. weight*1 << 10000.
	tx, utxos, weight := daTestTx(t, 0x13, 1<<32, 9999, 10)
	const currentMin = uint64(1)
	const minDaFee = uint64(1000)
	const surcharge = uint64(0)
	reject, daBytes, reason, err := RejectDaAnchorTxPolicy(tx, utxos, currentMin, minDaFee, surcharge)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if daBytes != 10 {
		t.Fatalf("daBytes=%d want=10", daBytes)
	}
	if !reject {
		t.Fatalf("expected reject: fee below DA-dominated floor; reason=%q", reason)
	}
	relayFloor := weight * currentMin
	const daFloor = uint64(10) * minDaFee
	const daSurcharge = uint64(10) * surcharge
	wantReason := wantStageCFloorReason(9999, daFloor, relayFloor, daFloor, daSurcharge, weight, 10)
	if reason != wantReason {
		t.Fatalf("reason=%q, want exact %q", reason, wantReason)
	}
}

// Boundary: fee == required_fee must admit; fee == required_fee - 1 must reject.
func TestRejectDaAnchorTxPolicy_BoundaryEqualAdmitsAndOneBelowRejects(t *testing.T) {
	// Construct DA-dominated case so we can compute the exact required_fee
	// without depending on the nondeterministic-but-fixed tx weight.
	const currentMin = uint64(0) // disable relay floor for this isolated boundary
	const minDaFee = uint64(7)
	const surcharge = uint64(0)
	const daBytes = uint64(10)
	required := daBytes * (minDaFee + surcharge) // = 70

	// fee == required must admit.
	txOK, utxosOK, _ := daTestTx(t, 0x14, 1<<20, required, int(daBytes))
	reject, _, reason, err := RejectDaAnchorTxPolicy(txOK, utxosOK, currentMin, minDaFee, surcharge)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if reject {
		t.Fatalf("expected admit at exact equality; reason=%q", reason)
	}

	// fee == required - 1 must reject.
	txBad, utxosBad, badWeight := daTestTx(t, 0x15, 1<<20, required-1, int(daBytes))
	reject2, observedDaBytes, reason2, err2 := RejectDaAnchorTxPolicy(txBad, utxosBad, currentMin, minDaFee, surcharge)
	if err2 != nil {
		t.Fatalf("unexpected err: %v", err2)
	}
	if observedDaBytes != daBytes {
		t.Fatalf("daBytes=%d want=%d", observedDaBytes, daBytes)
	}
	if !reject2 {
		t.Fatalf("expected reject at required-1; reason=%q", reason2)
	}
	wantReason := wantStageCFloorReason(required-1, required, 0, required, 0, badWeight, daBytes)
	if reason2 != wantReason {
		t.Fatalf("reason=%q, want exact %q", reason2, wantReason)
	}
}

// Non-DA tx must not be charged DA-specific floor/surcharge by Stage C.
// false_positive p2 + accepted_cases p5.
func TestRejectDaAnchorTxPolicy_NonDaTxNotCharged(t *testing.T) {
	tx, utxos, _ := nonDaTestTx(t, 0x16, 100, 0)
	const currentMin = uint64(0)  // no relay floor
	const minDaFee = uint64(1000) // would dominate if applied
	const surcharge = uint64(1000)
	reject, daBytes, reason, err := RejectDaAnchorTxPolicy(tx, utxos, currentMin, minDaFee, surcharge)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if daBytes != 0 {
		t.Fatalf("daBytes=%d want=0 for non-DA tx", daBytes)
	}
	if reject {
		t.Fatalf("non-DA tx must not be charged DA fee; reason=%q", reason)
	}
}

// Hostile matrix #5: overflow in any term must reject fail-closed,
// not silently fall through with a zero floor.
// TestRejectDaAnchorTxPolicy_RelayFloorProductAboveU64AdmitsClearingFee pins
// that a weight*currentMempoolMinFeeRate product above u64 is computed
// exactly rather than rejected. Before RUB-1127 this product went through
// mulU64NoOverflow, so any rate that overflowed the u64 product rejected
// every DA transaction regardless of its fee -- a product-overflow rejection
// the contract forbids, and one that already did not exist in
// mempool_fee_floor.go (feeRateBelowFloor) or in the consensus-CLI policy
// model (feeBelowRollingFloorPolicy).
func TestRejectDaAnchorTxPolicy_RelayFloorProductAboveU64AdmitsClearingFee(t *testing.T) {
	// One u64-max input paying nearly everything as fee, plus a second
	// u64-max input: sum_in crosses u64, so fee ~= 2^65 and only an exact
	// u128 floor can decide the comparison.
	tx, utxos, _ := daTestTx(t, 0x17, ^uint64(0), ^uint64(0)-100, 10)
	var second [32]byte
	second[0] = 0x17
	second[1] = 0xFF
	secondOp := consensus.Outpoint{Txid: second, Vout: 0}
	utxos[secondOp] = consensus.UtxoEntry{Value: ^uint64(0)}
	tx.Inputs = append(tx.Inputs, consensus.TxInput{PrevTxid: second, PrevVout: 0})

	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}
	// Smallest rate whose product with weight exceeds u64.
	currentMin := (^uint64(0) / weight) + 1
	exactFloor := mulU64Exact(weight, currentMin)
	if exactFloor.Cmp(consensus.Uint128FromU64(^uint64(0))) <= 0 {
		t.Fatalf("test premise: relay floor %s must exceed u64", exactFloor.String())
	}
	fee, err := computeFeeNoVerify(tx, utxos)
	if err != nil {
		t.Fatalf("computeFeeNoVerify: %v", err)
	}
	if fee.Cmp(exactFloor) < 0 {
		t.Fatalf("test premise: fee %s must clear the exact floor %s", fee.String(), exactFloor.String())
	}

	reject, _, reason, err := RejectDaAnchorTxPolicy(tx, utxos, currentMin, 1, 0)
	if err != nil {
		t.Fatalf("exact relay floor must not error: %v (reason=%q)", err, reason)
	}
	if reject {
		t.Fatalf("fee %s clears exact relay floor %s but was rejected: %q", fee.String(), exactFloor.String(), reason)
	}

	// One unit below the exact floor still rejects, with the honest Stage C
	// comparison reason rather than an arithmetic-capability error.
	belowFee, ok := exactFloor.CheckedSub(consensus.Uint128FromU64(1))
	if !ok {
		t.Fatal("exact floor must be reducible by one")
	}
	shortfall, ok := fee.CheckedSub(belowFee)
	if !ok {
		t.Fatal("fee must exceed the reduced floor")
	}
	tx.Outputs[0].Value += shortfall.Lo
	if shortfall.Hi != 0 {
		t.Fatalf("test premise: shortfall %s must fit an output value", shortfall.String())
	}
	reject, _, reason, err = RejectDaAnchorTxPolicy(tx, utxos, currentMin, 1, 0)
	if err != nil {
		t.Fatalf("one-below case must not error: %v (reason=%q)", err, reason)
	}
	if !reject {
		t.Fatal("fee one below the exact relay floor must reject")
	}
	if !strings.Contains(reason, "DA fee below Stage C floor") {
		t.Fatalf("expected exact Stage C comparison reason, got %q", reason)
	}
	if strings.Contains(reason, "overflow") {
		t.Fatalf("no overflow rejection may remain on the relay-floor term: %q", reason)
	}
}

func TestRejectDaAnchorTxPolicy_DaRequiredAdditionOverflowFailsClosed(t *testing.T) {
	tx, utxos, _ := daTestTx(t, 0x18, 100, 0, 1)
	// daBytes=1; pick minDaFee and surcharge so each multiplication fits
	// uint64 but their sum overflows.
	const minDaFee = uint64(1<<63) | 1
	const surcharge = uint64(1<<63) | 1
	reject, _, reason, err := RejectDaAnchorTxPolicy(tx, utxos, 1, minDaFee, surcharge)
	if !reject {
		t.Fatalf("expected reject on da_required addition overflow; reason=%q", reason)
	}
	if err == nil {
		t.Fatalf("expected error on overflow")
	}
	if !strings.Contains(reason, "overflow") {
		t.Fatalf("reason missing overflow diagnostic: %q", reason)
	}
}

// Hostile matrix #5 (continued): force daBytes * minDaFeeRate overflow
// independently. Surcharge=0 isolates the daFloor multiplication branch
// so a future patch that only guards the relay-floor or addition branches
// cannot silently ship.
func TestRejectDaAnchorTxPolicy_DaFloorMultiplicationOverflowFailsClosed(t *testing.T) {
	tx, utxos, _ := daTestTx(t, 0x1B, 100, 0, 4)
	// daBytes=4; minDaFee=^uint64(0) overflows daBytes*minDaFee while
	// relayFloor (weight*currentMin) does not. surcharge=0 so the helper
	// reaches the daFloor multiplication branch before any addition.
	const minDaFee = ^uint64(0)
	reject, _, reason, err := RejectDaAnchorTxPolicy(tx, utxos, 1, minDaFee, 0)
	if !reject {
		t.Fatalf("expected reject on da_fee_floor multiplication overflow; reason=%q", reason)
	}
	if err == nil {
		t.Fatalf("expected error on overflow")
	}
	if !strings.Contains(reason, "DA fee floor overflow") {
		t.Fatalf("reason missing DA-floor multiplication overflow diagnostic: %q", reason)
	}
}

// Hostile matrix #5 (continued): force daBytes * daSurchargePerByte overflow
// independently. minDaFee=0 lets the daFloor multiplication succeed (= 0);
// the helper must still reject when daSurcharge multiplication overflows.
func TestRejectDaAnchorTxPolicy_DaSurchargeMultiplicationOverflowFailsClosed(t *testing.T) {
	tx, utxos, _ := daTestTx(t, 0x1C, 100, 0, 4)
	// daBytes=4; surcharge=^uint64(0) overflows on multiplication while
	// daFloor (daBytes*0) is zero.
	const surcharge = ^uint64(0)
	reject, _, reason, err := RejectDaAnchorTxPolicy(tx, utxos, 1, 0, surcharge)
	if !reject {
		t.Fatalf("expected reject on da_surcharge multiplication overflow; reason=%q", reason)
	}
	if err == nil {
		t.Fatalf("expected error on overflow")
	}
	if !strings.Contains(reason, "DA surcharge overflow") {
		t.Fatalf("reason missing DA-surcharge multiplication overflow diagnostic: %q", reason)
	}
}

// All-zero policy + non-DA tx: helper short-circuits without computing fee.
func TestRejectDaAnchorTxPolicy_AllZeroNonDaShortCircuits(t *testing.T) {
	tx, utxos, _ := nonDaTestTx(t, 0x19, 50, 0)
	reject, daBytes, reason, err := RejectDaAnchorTxPolicy(tx, utxos, 0, 0, 0)
	if err != nil || reject {
		t.Fatalf("expected admit (all-zero policy + non-DA); reject=%v err=%v reason=%q", reject, err, reason)
	}
	if daBytes != 0 {
		t.Fatalf("daBytes=%d want=0", daBytes)
	}
}

// Caller drift / stale surcharge-only regression coverage: with old policy
// (surcharge-only, surcharge=1, minDaFee=0, currentMin=0) and DA tx that
// pays only the surcharge — admits. Same tx under Stage C with minDaFee=1
// must reject because da_required = da_payload_len * (minDaFee+surcharge).
func TestRejectDaAnchorTxPolicy_SurchargeOnlyRegressionCovered(t *testing.T) {
	// Old behavior reproduction: surcharge-only check would admit fee==daBytes*1.
	// New helper with minDaFee=1 gates on da_payload_len*(1+1)=20; fee=10 must reject.
	tx, utxos, weight := daTestTx(t, 0x1A, 100, 10, 10)
	reject, daBytes, reason, err := RejectDaAnchorTxPolicy(tx, utxos, 0, 1, 1)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if daBytes != 10 {
		t.Fatalf("daBytes=%d want=10", daBytes)
	}
	if !reject {
		t.Fatalf("expected reject under Stage C: fee=10 < da_required=20; reason=%q", reason)
	}
	wantReason := wantStageCFloorReason(10, 20, 0, 10, 10, weight, 10)
	if reason != wantReason {
		t.Fatalf("reason=%q, want exact %q", reason, wantReason)
	}
}

// nil tx guard.
func TestRejectDaAnchorTxPolicy_NilTxRejects(t *testing.T) {
	reject, _, _, err := RejectDaAnchorTxPolicy(nil, nil, 0, 0, 0)
	if !reject || err == nil {
		t.Fatalf("expected nil tx rejection")
	}
}
