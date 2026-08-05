package consensus

import (
	"encoding/json"
	"math/bits"
	"testing"
)

type uint128Holder struct {
	V Uint128 `json:"v"`
}

func readUint128JSON(raw string) (Uint128, bool) {
	var h uint128Holder
	if err := json.Unmarshal([]byte(raw), &h); err != nil {
		return Uint128{}, false
	}
	return h.V, true
}

// TestUint128JSONCanonicality pins the RUB-1127 fixed JSON rule. Mirrors Rust
// `uint128_json::tests`; every accepted and rejected row below is a row of the
// contract.
func TestUint128JSONCanonicality(t *testing.T) {
	t.Run("writes canonical decimal strings", func(t *testing.T) {
		for _, value := range []Uint128{
			{},
			Uint128FromU64(1),
			Uint128FromU64(^uint64(0)),
			{Hi: 1, Lo: 0},
			{Hi: ^uint64(0), Lo: ^uint64(0)},
		} {
			encoded, err := json.Marshal(uint128Holder{V: value})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			want := `{"v":"` + value.String() + `"}`
			if string(encoded) != want {
				t.Fatalf("encoded=%s want=%s", encoded, want)
			}
			// Round-trips exactly, with no JSON-number precision dependence.
			got, ok := readUint128JSON(string(encoded))
			if !ok || got.Cmp(value) != 0 {
				t.Fatalf("round-trip got=%v ok=%v want=%s", got, ok, value.String())
			}
		}
	})

	t.Run("accepts legacy numeric tokens up to u64", func(t *testing.T) {
		for raw, want := range map[string]Uint128{
			`{"v":0}`:                    {},
			`{"v":18446744073709551615}`: Uint128FromU64(^uint64(0)),
		} {
			got, ok := readUint128JSON(raw)
			if !ok || got.Cmp(want) != 0 {
				t.Fatalf("%s: got=%v ok=%v want=%s", raw, got, ok, want.String())
			}
		}
	})

	t.Run("accepts canonical strings through u128 max", func(t *testing.T) {
		for raw, want := range map[string]Uint128{
			`{"v":"0"}`:                    {},
			`{"v":"18446744073709551616"}`: {Hi: 1, Lo: 0},
			`{"v":"340282366920938463463374607431768211455"}`: {Hi: ^uint64(0), Lo: ^uint64(0)},
		} {
			got, ok := readUint128JSON(raw)
			if !ok || got.Cmp(want) != 0 {
				t.Fatalf("%s: got=%v ok=%v want=%s", raw, got, ok, want.String())
			}
		}
	})

	t.Run("rejects non-canonical and out-of-domain tokens", func(t *testing.T) {
		for _, raw := range []string{
			// A numeric token above u64: the widened domain is only
			// reachable through the string form.
			`{"v":18446744073709551616}`,
			`{"v":-1}`,
			`{"v":1.0}`,
			`{"v":""}`,
			`{"v":"00"}`,
			`{"v":"01"}`,
			`{"v":"+1"}`,
			`{"v":"-1"}`,
			`{"v":" 1"}`,
			`{"v":"1 "}`,
			`{"v":"1.0"}`,
			`{"v":"1e3"}`,
			// u128 max + 1
			`{"v":"340282366920938463463374607431768211456"}`,
		} {
			if _, ok := readUint128JSON(raw); ok {
				t.Fatalf("accepted non-canonical token: %s", raw)
			}
		}
	})
}

// TestCompareFeeRateRetainsAll192ProductBits pins the exact fee-rate
// comparison. Mirrors Rust `fee_rate_product_retains_all_192_bits`.
func TestCompareFeeRateRetainsAll192ProductBits(t *testing.T) {
	// Significant product bits above 127: a u128-only cross-product would
	// wrap and misorder these.
	feeA := Uint128{Hi: 1 << 63}
	feeB := Uint128{Hi: 1<<63 - 1, Lo: ^uint64(0)}
	if got := CompareFeeRate(feeA, 1, feeB, 1); got != 1 {
		t.Fatalf("compare=%d, want 1", got)
	}
	// Exact ratio equality with distinct fees and weights.
	if got := CompareFeeRate(Uint128{Hi: 1 << 36}, 2, Uint128{Hi: 1 << 35}, 1); got != 0 {
		t.Fatalf("ratio-equal compare=%d, want 0", got)
	}
	// Zero weight is an uncomputable rate on either side.
	if got := CompareFeeRate(Uint128FromU64(1), 0, Uint128FromU64(1), 1); got != 0 {
		t.Fatalf("zero-weight compare=%d, want 0", got)
	}
	if got := CompareFeeRate(Uint128FromU64(1), 1, Uint128FromU64(1), 0); got != 0 {
		t.Fatalf("zero-weight compare=%d, want 0", got)
	}
}

// TestFeeBelowRateIsExactAtTheBoundary pins that a required amount above u64
// no longer forces an automatic reject. Mirrors Rust
// `fee_below_rate_is_exact_at_the_boundary`.
func TestFeeBelowRateIsExactAtTheBoundary(t *testing.T) {
	// weight*rate = u64max^2, well above u64.
	hi, lo := bits.Mul64(^uint64(0), ^uint64(0))
	required := Uint128{Hi: hi, Lo: lo}
	below, ok := required.CheckedSub(Uint128FromU64(1))
	if !ok {
		t.Fatal("boundary underflow")
	}
	if !FeeBelowRate(below, ^uint64(0), ^uint64(0)) {
		t.Fatal("one below the required amount must be below floor")
	}
	if FeeBelowRate(required, ^uint64(0), ^uint64(0)) {
		t.Fatal("exactly the required amount must clear the floor")
	}
}

func TestU128Helpers_SubUnderflowAndToU64Overflow(t *testing.T) {
	// subU128 underflow
	_, err := subU128(u128{hi: 0, lo: 0}, u128{hi: 0, lo: 1})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}

	// u128ToU64 overflow
	_, err = u128ToU64(u128{hi: 1, lo: 0})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestCheckSpendCovenant_SupportedTypes(t *testing.T) {
	if err := checkSpendCovenant(COV_TYPE_P2PK, nil); err != nil {
		t.Fatalf("CORE_P2PK: %v", err)
	}

	if err := checkSpendCovenant(COV_TYPE_VAULT, validVaultCovenantDataForP2PKOutput()); err != nil {
		t.Fatalf("CORE_VAULT: %v", err)
	}

	msKeyID := filled32(0x33)
	if err := checkSpendCovenant(COV_TYPE_MULTISIG, encodeMultisigCovenantData(1, [][32]byte{msKeyID})); err != nil {
		t.Fatalf("CORE_MULTISIG: %v", err)
	}

	claimKeyID := filled32(0x44)
	refundKeyID := filled32(0x45)
	htlcData := encodeHTLCCovenantData(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)
	if err := checkSpendCovenant(COV_TYPE_HTLC, htlcData); err != nil {
		t.Fatalf("CORE_HTLC: %v", err)
	}
}

func TestCheckSpendCovenant_Errors(t *testing.T) {
	if err := checkSpendCovenant(COV_TYPE_VAULT, nil); err == nil {
		t.Fatalf("expected error for invalid CORE_VAULT covenant_data")
	}
	if err := checkSpendCovenant(COV_TYPE_MULTISIG, nil); err == nil {
		t.Fatalf("expected error for invalid CORE_MULTISIG covenant_data")
	}
	if err := checkSpendCovenant(COV_TYPE_HTLC, nil); err == nil {
		t.Fatalf("expected error for invalid CORE_HTLC covenant_data")
	}
	err := checkSpendCovenant(0x9999, []byte{0x01})
	if err == nil {
		t.Fatalf("expected error for unknown covenant type")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}

	err = checkSpendCovenant(COV_TYPE_CORE_EXT, []byte{0x01})
	if err == nil {
		t.Fatalf("expected error for unassigned CORE_EXT (0x0102) covenant_type")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasicWorkRejectsUnsupportedTxKindViaPrehashCache(t *testing.T) {
	var prevTxid [32]byte
	prevTxid[0] = 0x91
	tx := &Tx{
		Version: 1,
		TxKind:  0xff,
		TxNonce: 1,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0x7FFFFFFF,
		}},
	}
	_, _, err := applyNonCoinbaseTxBasicWork(nonCoinbaseApplyWorkInput{
		tx:      tx,
		utxoSet: map[Outpoint]UtxoEntry{},
		height:  1,
	})
	if err == nil {
		t.Fatal("expected unsupported tx_kind error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}
