package consensus

import (
	"math"
	"testing"
)

// RUB-879: overflow coverage for the shared weight engine using only
// defined-behavior inputs. Each accumulation helper takes its accumulator as a
// parameter, so overflow is reached with real small slices by seeding the
// accumulator near math.MaxUint64. Fabricated slice headers over undersized
// backing memory are forbidden in this package: they are undefined behavior
// and trigger a checkptr fatal under -race.

func TestAddU64_Boundary(t *testing.T) {
	if _, err := addU64(math.MaxUint64, 1); err == nil {
		t.Fatal("addU64(MaxUint64, 1) should overflow")
	} else if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}

	got, err := addU64(math.MaxUint64-1, 1)
	if err != nil {
		t.Fatalf("addU64(MaxUint64-1, 1): %v", err)
	}
	if got != math.MaxUint64 {
		t.Fatalf("addU64(MaxUint64-1, 1)=%d, want MaxUint64", got)
	}
}

func TestMulU64_WitnessDiscountBoundary(t *testing.T) {
	// The exact arithmetic of the base-weight computation:
	// mulU64(WITNESS_DISCOUNT_DIVISOR, baseSize) with baseSize = 2^62 gives
	// 4 * 2^62 = 2^64 > MaxUint64.
	if _, err := mulU64(WITNESS_DISCOUNT_DIVISOR, uint64(1)<<62); err == nil {
		t.Fatal("mulU64(WITNESS_DISCOUNT_DIVISOR, 1<<62) should overflow")
	} else if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}

	// Largest non-overflowing operand for the same multiplier.
	const maxQuotient = uint64(math.MaxUint64) / WITNESS_DISCOUNT_DIVISOR
	got, err := mulU64(WITNESS_DISCOUNT_DIVISOR, maxQuotient)
	if err != nil {
		t.Fatalf("mulU64(WITNESS_DISCOUNT_DIVISOR, MaxUint64/WITNESS_DISCOUNT_DIVISOR): %v", err)
	}
	if got != WITNESS_DISCOUNT_DIVISOR*maxQuotient {
		t.Fatalf("mulU64=%d, want %d", got, uint64(WITNESS_DISCOUNT_DIVISOR)*maxQuotient)
	}
}

func TestAddInputSizes_SeededScriptSigOverflow(t *testing.T) {
	// Per input, addInputSizes adds 36 (prev_txid+prev_vout), then
	// compactSizeLen(len(ScriptSig)), then len(ScriptSig), then 4 (sequence).
	// With a 32-byte ScriptSig (compact size 1) and seed = MaxUint64-68 the
	// running total reaches MaxUint64-31 before the script_sig length add, so
	// adding 32 is the first add that overflows.
	seed := uint64(math.MaxUint64 - 68)
	inputs := []TxInput{{ScriptSig: make([]byte, 32)}}

	_, err := addInputSizes(seed, inputs)
	if err == nil {
		t.Fatal("expected overflow at the script_sig length add")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestAddOutputSizes_SeededCovenantDataOverflow(t *testing.T) {
	// Per output, addOutputSizes adds 10 (value+covenant_type), then
	// compactSizeLen(covLen), then covLen. With 32-byte CovenantData (compact
	// size 1) and seed = MaxUint64-42 the running total reaches MaxUint64-31
	// before the covenant_data length add, so adding 32 is the first add that
	// overflows.
	seed := uint64(math.MaxUint64 - 42)
	outputs := []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, 32)}}

	_, _, err := addOutputSizes(seed, outputs)
	if err == nil {
		t.Fatal("expected overflow at the covenant_data length add")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestAddWitnessItemSerialSize_SeededPubkeyOverflow(t *testing.T) {
	// Per item, addWitnessItemSerialSize adds 1 (suite_id), then
	// compactSizeLen(len(Pubkey)), then len(Pubkey), then
	// compactSizeLen(len(Signature)), then len(Signature). With a 32-byte
	// Pubkey (compact size 1) and seed = MaxUint64-33 the running total reaches
	// MaxUint64-31 before the pubkey length add, so adding 32 fails there —
	// before the signature adds are reached.
	seed := uint64(math.MaxUint64 - 33)
	item := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, 32), Signature: make([]byte, 4)}

	_, err := addWitnessItemSerialSize(seed, item)
	if err == nil {
		t.Fatal("expected overflow at the pubkey length add")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestAddWitnessItemSerialSize_SeededSignatureOverflow(t *testing.T) {
	// Same add sequence as above with a 4-byte Pubkey and 32-byte Signature:
	// the adds before the signature length are 1 + 1 + 4 + 1 = 7, so
	// seed = MaxUint64-38 reaches MaxUint64-31 right before the signature
	// length add, and adding 32 is the first add that overflows.
	seed := uint64(math.MaxUint64 - 38)
	item := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, 4), Signature: make([]byte, 32)}

	_, err := addWitnessItemSerialSize(seed, item)
	if err == nil {
		t.Fatal("expected overflow at the signature length add")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestAddWitnessItemSize_SeededSigCostOverflow(t *testing.T) {
	// witnessSeed is small so every serial-size add succeeds; sigCostSeed >= 1
	// with a MaxUint64 sig cost makes addU64(sigCost, cost) the failing add.
	item := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, 32), Signature: make([]byte, 4)}
	sigCostFn := func(w WitnessItem) (uint64, error) { return math.MaxUint64, nil }

	_, _, err := addWitnessItemSize(0, 1, item, sigCostFn)
	if err == nil {
		t.Fatal("expected overflow at the sig cost add")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestTxWeightComponents_SigCostOverflowPropagates(t *testing.T) {
	// End-to-end through the shared engine with zero fabrication: two real
	// non-sentinel witness items and a sig cost of MaxUint64 each. The first
	// item's cost accumulates to MaxUint64; the second item's sig cost add
	// overflows, and txWeightComponents must propagate that error.
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0, ScriptSig: make([]byte, 4)}},
		Outputs: []TxOutput{{Value: 1000, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, 8)}},
		Witness: []WitnessItem{
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, 32), Signature: make([]byte, 4)},
			{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, 32), Signature: make([]byte, 4)},
		},
	}
	sigCostFn := func(w WitnessItem) (uint64, error) { return math.MaxUint64, nil }

	_, _, _, err := txWeightComponents(tx, sigCostFn)
	if err == nil {
		t.Fatal("expected sig cost accumulation overflow to propagate")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}
