//! Canonical JSON encoding for widened (u128) monetary values.
//!
//! Mirrors Go `consensus.Uint128`'s `MarshalJSON`/`UnmarshalJSON` in
//! `clients/go/consensus/utxo_u128.go` byte for byte:
//!
//! * every widened value is WRITTEN as a JSON string holding canonical
//!   unsigned base-10 decimal: exactly `"0"` or `[1-9][0-9]*`, value
//!   `<= 2^128-1`. A widened monetary integer must not depend on
//!   interoperable JSON-number precision (RFC 8259 §6);
//! * a value is READ from either that canonical string form (full u128
//!   range) or a legacy JSON integer token, which stays bounded to
//!   `<= 2^64-1` exactly as the pre-widening readers were;
//! * everything else is rejected: a numeric token above u64, a negative, a
//!   sign, surrounding whitespace, a leading zero, the empty string, a
//!   fraction, an exponent, a non-digit, and any value above u128.
//!
//! Omission semantics are the caller's: `Option` fields keep their
//! `skip_serializing_if` so widening never forces an absent zero-valued
//! field present.

use serde::de::{Error as DeError, Unexpected};
use serde::{Deserialize, Deserializer, Serializer};

/// Parses the canonical unsigned base-10 decimal form.
///
/// Accepts exactly `"0"` or `[1-9][0-9]*` with value `<= 2^128-1`.
pub fn parse_canonical_decimal(s: &str) -> Option<u128> {
    if s.is_empty() {
        return None;
    }
    if s.starts_with('0') && s.len() != 1 {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Parsing an all-ASCII-digit, no-leading-zero string can only fail by
    // exceeding u128, which is exactly the remaining rejection.
    s.parse::<u128>().ok()
}

/// Renders the canonical unsigned base-10 decimal form.
pub fn to_canonical_decimal(value: u128) -> String {
    value.to_string()
}

/// Serializes a `u128` as its canonical decimal string.
pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&to_canonical_decimal(*value))
}

/// Serializes an `Option<u128>` as a canonical decimal string, preserving
/// `None` for callers that also carry `skip_serializing_if`.
pub fn serialize_opt<S: Serializer>(
    value: &Option<u128>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(v) => serializer.serialize_str(&to_canonical_decimal(*v)),
        None => serializer.serialize_none(),
    }
}

/// Untagged reader accepting the canonical string form or a legacy
/// nonnegative JSON integer token bounded to u64.
#[derive(Deserialize)]
#[serde(untagged)]
enum Uint128Token {
    // u64 (not u128) is deliberate: a legacy numeric token stays bounded to
    // the pre-widening domain, so `18446744073709551616` as a bare number is
    // rejected rather than silently widened.
    LegacyNumber(u64),
    Canonical(String),
}

fn from_token<E: DeError>(token: Uint128Token) -> Result<u128, E> {
    match token {
        Uint128Token::LegacyNumber(v) => Ok(u128::from(v)),
        Uint128Token::Canonical(s) => parse_canonical_decimal(&s).ok_or_else(|| {
            E::invalid_value(
                Unexpected::Str(&s),
                &"canonical unsigned decimal string \"0\" or [1-9][0-9]* within u128",
            )
        }),
    }
}

/// Deserializes a `u128` from the canonical string form or a legacy u64
/// numeric token.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    from_token(Uint128Token::deserialize(deserializer)?)
}

/// Deserializes an `Option<u128>`; an explicit JSON `null` reads as `None`.
pub fn deserialize_opt<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u128>, D::Error> {
    match Option::<Uint128Token>::deserialize(deserializer)? {
        Some(token) => from_token(token).map(Some),
        None => Ok(None),
    }
}

/// Compares `fee_a/weight_a` against `fee_b/weight_b` by exact
/// cross-multiplication over all 192 product bits. A zero weight on either
/// side is an uncomputable rate and compares equal, matching Go
/// `consensus.CompareFeeRate`.
pub fn compare_fee_rate(
    fee_a: u128,
    weight_a: u64,
    fee_b: u128,
    weight_b: u64,
) -> core::cmp::Ordering {
    if weight_a == 0 || weight_b == 0 {
        return core::cmp::Ordering::Equal;
    }
    mul_u128_by_u64(fee_a, weight_b).cmp(&mul_u128_by_u64(fee_b, weight_a))
}

/// Exact 192-bit product of a u128 by a u64, as `(high 128 bits, low 64
/// bits)`. Every product bit is retained: no truncation, saturation, or
/// floating point. Mirrors Go `mulUint128ByU64`.
fn mul_u128_by_u64(a: u128, b: u64) -> (u128, u64) {
    let b = u128::from(b);
    let low_part = (a & u128::from(u64::MAX)) * b;
    let high_part = (a >> 64) * b;
    // high_part <= (2^64-1)^2 and (low_part >> 64) <= 2^64-2, so the sum
    // cannot overflow u128.
    (high_part + (low_part >> 64), low_part as u64)
}

/// Reports `fee < weight * rate` exactly. `weight * rate` is the full
/// 128-bit product, so a required amount above u64 no longer forces an
/// automatic reject. Mirrors Go `consensus.FeeBelowRate`.
pub fn fee_below_rate(fee: u128, weight: u64, rate: u64) -> bool {
    fee < u128::from(weight) * u128::from(rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors Go `TestUint128JSONCanonicality`. Every accepted and rejected
    /// row below is a row of the RUB-1127 contract.
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Holder {
        #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
        v: u128,
    }

    fn read(raw: &str) -> Option<u128> {
        serde_json::from_str::<Holder>(raw).ok().map(|h| h.v)
    }

    #[test]
    fn writes_canonical_decimal_strings() {
        for value in [0u128, 1, u128::from(u64::MAX), 1u128 << 64, u128::MAX] {
            let encoded = serde_json::to_string(&Holder { v: value }).expect("encode");
            assert_eq!(encoded, format!("{{\"v\":\"{value}\"}}"));
            // Round-trips exactly, with no JSON-number precision dependence.
            assert_eq!(read(&encoded), Some(value));
        }
    }

    #[test]
    fn accepts_legacy_numeric_tokens_up_to_u64() {
        assert_eq!(read("{\"v\":0}"), Some(0));
        assert_eq!(
            read("{\"v\":18446744073709551615}"),
            Some(u128::from(u64::MAX))
        );
    }

    #[test]
    fn rejects_numeric_token_above_u64() {
        // The widened domain is only reachable through the string form.
        assert_eq!(read("{\"v\":18446744073709551616}"), None);
    }

    #[test]
    fn accepts_canonical_strings_through_u128_max() {
        assert_eq!(read("{\"v\":\"0\"}"), Some(0));
        assert_eq!(read("{\"v\":\"18446744073709551616\"}"), Some(1u128 << 64));
        assert_eq!(
            read("{\"v\":\"340282366920938463463374607431768211455\"}"),
            Some(u128::MAX)
        );
    }

    #[test]
    fn rejects_non_canonical_strings() {
        for bad in [
            "\"\"",
            "\"00\"",
            "\"01\"",
            "\"+1\"",
            "\"-1\"",
            "\" 1\"",
            "\"1 \"",
            "\"1.0\"",
            "\"1e3\"",
            // u128 max + 1
            "\"340282366920938463463374607431768211456\"",
        ] {
            assert_eq!(read(&format!("{{\"v\":{bad}}}")), None, "accepted {bad}");
        }
    }

    #[test]
    fn rejects_negative_and_fractional_numeric_tokens() {
        assert_eq!(read("{\"v\":-1}"), None);
        assert_eq!(read("{\"v\":1.0}"), None);
    }

    #[test]
    fn fee_rate_product_retains_all_192_bits() {
        // Adjacent products at bit 127 (2^127 against 2^127-1): ordering
        // only, both still inside u128.
        let fee_a = 1u128 << 127;
        let fee_b = (1u128 << 127) - 1;
        assert_eq!(
            compare_fee_rate(fee_a, 1, fee_b, 1),
            core::cmp::Ordering::Greater
        );
        // Products ABOVE 128 bits, where a wrapping or saturating u128
        // cross-product reverses the verdict. u128::MAX at weight 1 outranks
        // u128::MAX at weight 2: the exact products are 2^129-2 against
        // 2^128-1, which wrap to 2^128-2 against 2^128-1.
        assert_eq!(
            compare_fee_rate(u128::MAX, 1, u128::MAX, 2),
            core::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_fee_rate(u128::MAX, 2, u128::MAX, 1),
            core::cmp::Ordering::Less
        );
        // Product exactly 2^128 (against 2^126): wrapping annihilates it to
        // zero and reverses the verdict.
        assert_eq!(
            compare_fee_rate(1u128 << 127, 1, 1u128 << 126, 2),
            core::cmp::Ordering::Greater
        );
        // Exact ratio equality with distinct fees and weights.
        assert_eq!(
            compare_fee_rate(1u128 << 100, 2, 1u128 << 99, 1),
            core::cmp::Ordering::Equal
        );
        // Zero weight is an uncomputable rate on either side.
        assert_eq!(compare_fee_rate(1, 0, 1, 1), core::cmp::Ordering::Equal);
        assert_eq!(compare_fee_rate(1, 1, 1, 0), core::cmp::Ordering::Equal);
    }

    #[test]
    fn fee_below_rate_is_exact_at_the_boundary() {
        // weight*rate = u64::MAX^2, well above u64: no auto-reject.
        let required = u128::from(u64::MAX) * u128::from(u64::MAX);
        assert!(fee_below_rate(required - 1, u64::MAX, u64::MAX));
        assert!(!fee_below_rate(required, u64::MAX, u64::MAX));
    }
}
