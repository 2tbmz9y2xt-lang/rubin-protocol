package consensus

import (
	"encoding/json"
	"errors"
	"math/big"
	"math/bits"
)

// Uint128FromU64 widens a u64 into the exact u128 domain.
func Uint128FromU64(v uint64) Uint128 { return Uint128{Lo: v} }

// IsZero reports whether the value is exactly zero.
func (v Uint128) IsZero() bool { return v.Hi == 0 && v.Lo == 0 }

// Cmp compares two u128 values, returning -1, 0, or +1.
func (v Uint128) Cmp(other Uint128) int {
	return cmpU128(uint128ToInternal(v), uint128ToInternal(other))
}

// CheckedAdd returns v+other and ok=false on u128 overflow. It never wraps,
// saturates, or narrows.
func (v Uint128) CheckedAdd(other Uint128) (Uint128, bool) {
	lo, carry := bits.Add64(v.Lo, other.Lo, 0)
	hi, carry2 := bits.Add64(v.Hi, other.Hi, carry)
	if carry2 != 0 {
		return Uint128{}, false
	}
	return Uint128{Hi: hi, Lo: lo}, true
}

// CheckedSub returns v-other and ok=false on u128 underflow. It never wraps
// or saturates.
func (v Uint128) CheckedSub(other Uint128) (Uint128, bool) {
	lo, borrow := bits.Sub64(v.Lo, other.Lo, 0)
	hi, borrow2 := bits.Sub64(v.Hi, other.Hi, borrow)
	if borrow2 != 0 {
		return Uint128{}, false
	}
	return Uint128{Hi: hi, Lo: lo}, true
}

// Big returns the exact value as a new independent big.Int for decimal rendering
// and explicit bridging to existing arbitrary-precision subsidy/state code.
func (v Uint128) Big() *big.Int {
	b := new(big.Int).SetUint64(v.Hi)
	b.Lsh(b, 64)
	return b.Or(b, new(big.Int).SetUint64(v.Lo))
}

// String renders the canonical unsigned base-10 decimal form: exactly "0"
// or [1-9][0-9]*, never signed, padded, grouped, or truncated.
func (v Uint128) String() string { return v.Big().String() }

var errUint128NotCanonical = errors.New("uint128: value is not a canonical unsigned decimal string")

// checkCanonicalDecimalForm reports whether s is exactly "0" or [1-9][0-9]*,
// rejecting empty input, leading zeroes, signs, whitespace, fractions,
// exponents, and any non-digit byte. It is lexical only: the u128 range check
// belongs to ParseUint128Decimal.
func checkCanonicalDecimalForm(s string) error {
	if s == "" {
		return errUint128NotCanonical
	}
	if s[0] == '0' && len(s) != 1 {
		return errUint128NotCanonical
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return errUint128NotCanonical
		}
	}
	return nil
}

// ParseUint128Decimal parses the canonical unsigned base-10 decimal form.
// It accepts exactly "0" or [1-9][0-9]* with value <= 2^128-1 and rejects
// empty input, leading zeroes, signs, whitespace, fractions, exponents, any
// non-digit byte, and any value above u128.
func ParseUint128Decimal(s string) (Uint128, error) {
	if err := checkCanonicalDecimalForm(s); err != nil {
		return Uint128{}, err
	}
	b, ok := new(big.Int).SetString(s, 10)
	if !ok || b.BitLen() > 128 {
		return Uint128{}, errUint128NotCanonical
	}
	hi := new(big.Int).Rsh(b, 64)
	lo := new(big.Int).Sub(b, new(big.Int).Lsh(hi, 64))
	return Uint128{Hi: hi.Uint64(), Lo: lo.Uint64()}, nil
}

// MarshalJSON always writes the canonical decimal string form, so a widened
// value never depends on interoperable JSON-number precision (RFC 8259 §6).
func (v Uint128) MarshalJSON() ([]byte, error) { return json.Marshal(v.String()) }

// UnmarshalJSON accepts either the canonical decimal string form (full u128
// range) or a legacy JSON integer token, which is bounded to u64 exactly as
// the pre-widening readers were. A numeric token above u64, a negative, a
// fraction, an exponent, or a null is rejected; a string token must be
// canonical.
//
// The null reject is explicit because json.Unmarshal of null into a uint64 is
// a documented no-op: without it the legacy branch below would leave the value
// at zero and report success, silently reading a null fee position as zero.
// Omission semantics are unaffected — encoding/json sets a null optional
// (*Uint128) field to nil without calling this method, matching Rust
// uint128_json::deserialize_opt.
func (v *Uint128) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return errUint128NotCanonical
	}
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		parsed, err := ParseUint128Decimal(s)
		if err != nil {
			return err
		}
		*v = parsed
		return nil
	}
	var legacy uint64
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	*v = Uint128FromU64(legacy)
	return nil
}

// u192 is the exact 192-bit product of a Uint128 by a uint64: hi holds the
// top 128 bits and lo the low 64. Every product bit is retained, so no
// fee-rate comparison truncates, saturates, or falls back to floating point.
type u192 struct {
	hi Uint128
	lo uint64
}

func mulUint128ByU64(a Uint128, b uint64) u192 {
	loCarry, lo := bits.Mul64(a.Lo, b)
	hiHi, hiLo := bits.Mul64(a.Hi, b)
	mid, carry := bits.Add64(hiLo, loCarry, 0)
	// hiHi <= 2^64-2 for any u64 operands, so hiHi+carry cannot overflow.
	return u192{hi: Uint128{Hi: hiHi + carry, Lo: mid}, lo: lo}
}

func cmpU192(a u192, b u192) int {
	if c := a.hi.Cmp(b.hi); c != 0 {
		return c
	}
	switch {
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	default:
		return 0
	}
}

// CompareFeeRate compares feeA/weightA against feeB/weightB by exact
// cross-multiplication over all 192 product bits. A zero weight on either
// side is an uncomputable rate and compares equal, matching the pre-widening
// helpers this replaces.
func CompareFeeRate(feeA Uint128, weightA uint64, feeB Uint128, weightB uint64) int {
	if weightA == 0 || weightB == 0 {
		return 0
	}
	return cmpU192(mulUint128ByU64(feeA, weightB), mulUint128ByU64(feeB, weightA))
}

// FeeBelowRate reports fee < weight*rate exactly. weight*rate is a full
// 128-bit product, so a product above u64 no longer forces a reject: the
// comparison stays exact through the whole u128 fee domain.
func FeeBelowRate(fee Uint128, weight uint64, rate uint64) bool {
	hi, lo := bits.Mul64(weight, rate)
	return fee.Cmp(Uint128{Hi: hi, Lo: lo}) < 0
}

func addU64ToU128WithCode(x u128, v uint64, code ErrorCode) (u128, error) {
	lo, carry := bits.Add64(x.lo, v, 0)
	hi, carry2 := bits.Add64(x.hi, 0, carry)
	if carry2 != 0 {
		return u128{}, txerr(code, "u128 overflow")
	}
	return u128{hi: hi, lo: lo}, nil
}

func cmpU128(a u128, b u128) int {
	if a.hi < b.hi {
		return -1
	}
	if a.hi > b.hi {
		return 1
	}
	if a.lo < b.lo {
		return -1
	}
	if a.lo > b.lo {
		return 1
	}
	return 0
}

func subU128(a u128, b u128) (u128, error) {
	if cmpU128(a, b) < 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 underflow")
	}
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	hi, borrow2 := bits.Sub64(a.hi, b.hi, borrow)
	if borrow2 != 0 {
		return u128{}, txerr(TX_ERR_PARSE, "u128 underflow")
	}
	return u128{hi: hi, lo: lo}, nil
}
