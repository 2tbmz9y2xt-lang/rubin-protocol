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
    // `from_str_radix` on an all-ASCII-digit, no-leading-zero string can only
    // fail by exceeding u128, which is exactly the remaining rejection.
    u128::from_str_radix(s, 10).ok()
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
pub fn compare_fee_rate(fee_a: u128, weight_a: u64, fee_b: u128, weight_b: u64) -> core::cmp::Ordering {
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
