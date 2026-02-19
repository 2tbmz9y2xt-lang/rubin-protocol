use crate::encode::block_header_bytes;
use crate::{
    BLOCK_ERR_TARGET_INVALID, BLOCK_ERR_TIMESTAMP_OLD, BlockHeader, MAX_TARGET,
    TARGET_BLOCK_INTERVAL, WINDOW_SIZE,
};
use rubin_crypto::CryptoProvider;

/// Compute the SHA3-256 digest of a block header using the given cryptographic provider.
///
/// # Returns
///
/// The 32-byte SHA3-256 hash of the serialized block header, or an error string returned by the provider.
///
/// # Examples
///
/// ```
/// // `provider` implements `CryptoProvider` and `header` is a `BlockHeader`.
/// let hash = block_header_hash(&provider, &header).expect("hash computed");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn block_header_hash(
    provider: &dyn CryptoProvider,
    h: &BlockHeader,
) -> Result<[u8; 32], String> {
    provider.sha3_256(&block_header_bytes(h))
}

/// Compute the block subsidy (coinbase reward) for a given block height.
///
/// If `height` is greater than or equal to the total subsidy duration the reward is 0.
/// Otherwise the total subsidy is divided evenly across the subsidy duration; the
/// first `rem = SUBSIDY_TOTAL_MINED % SUBSIDY_DURATION_BLOCKS` heights receive `base + 1`
/// and the remaining heights receive `base`, where
/// `base = SUBSIDY_TOTAL_MINED / SUBSIDY_DURATION_BLOCKS`.
///
/// # Examples
///
/// ```
/// // first block (height 0) receives either base or base + 1 depending on remainder
/// let r0 = block_reward_for_height(0);
/// // after subsidy duration the reward is zero
/// let r_end = block_reward_for_height(1_314_900);
/// assert!(r0 > 0);
/// assert_eq!(r_end, 0);
/// ```
pub(crate) fn block_reward_for_height(height: u64) -> u64 {
    const SUBSIDY_TOTAL_MINED: u64 = 9_900_000_000_000_000;
    const SUBSIDY_DURATION_BLOCKS: u64 = 1_314_900;

    if height >= SUBSIDY_DURATION_BLOCKS {
        return 0;
    }

    let base = SUBSIDY_TOTAL_MINED / SUBSIDY_DURATION_BLOCKS;
    let rem = SUBSIDY_TOTAL_MINED % SUBSIDY_DURATION_BLOCKS;
    if height < rem { base + 1 } else { base }
}

/// Compute the median timestamp from up to the last 11 past block headers for a given height.
///
/// Returns an error when `height` is zero or `headers` is empty (returns `BLOCK_ERR_TIMESTAMP_OLD`).
/// The function considers at most `min(11, height, headers.len())` most-recent headers, sorts their
/// timestamps, and returns the middle value (median).
///
/// # Examples
///
/// ```
/// // Assuming `headers` is a slice of `BlockHeader` with a public `timestamp: u64` field:
/// // let median = median_past_timestamp(&headers, current_height)?;
/// // assert!(median > 0);
/// ```
pub(crate) fn median_past_timestamp(headers: &[BlockHeader], height: u64) -> Result<u64, String> {
    if height == 0 || headers.is_empty() {
        return Err(BLOCK_ERR_TIMESTAMP_OLD.into());
    }
    let mut k = 11u64;
    if height < k {
        k = height;
    }
    let mut limit = k as usize;
    if headers.len() < limit {
        limit = headers.len();
    }
    let mut timestamps = Vec::with_capacity(limit);
    for i in 0..limit {
        timestamps.push(headers[headers.len() - 1 - i].timestamp);
    }
    timestamps.sort_unstable();
    Ok(timestamps[(timestamps.len() - 1) / 2])
}

// ----- u256 arithmetic (big-endian 4-limb representation) -----

/// Convert a 32-byte big-endian array into a four-limb 64-bit big-endian representation.
///
/// Each limb is an 8-byte chunk interpreted as a big-endian `u64`. Limb index 0 holds the most-significant
/// 64 bits of the 256-bit value and limb index 3 holds the least-significant 64 bits.
///
/// # Examples
///
/// ```
/// let bytes: [u8; 32] = [
///     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // most significant limb
///     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
///     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
///     0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, // least significant limb
/// ];
/// let limbs = u256_from_be_bytes32(&bytes);
/// assert_eq!(limbs[0], 0x0102030405060708u64);
/// assert_eq!(limbs[3], 0x191a1b1c1d1e1f20u64);
/// ```
pub(crate) fn u256_from_be_bytes32(b: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let start = i * 8;
        limbs[i] = u64::from_be_bytes([
            b[start],
            b[start + 1],
            b[start + 2],
            b[start + 3],
            b[start + 4],
            b[start + 5],
            b[start + 6],
            b[start + 7],
        ]);
    }
    limbs
}

/// Serialize a 4-limb big-endian 256-bit value into a 32-byte big-endian array.
///
/// The input `limbs` are ordered most-significant first (limbs[0]) to least-significant last (limbs[3]).
///
/// # Returns
///
/// `[u8; 32]` containing the big-endian byte representation of the 256-bit value.
///
/// # Examples
///
/// ```
/// let limbs: [u64; 4] = [0x0123456789ABCDEF, 0x0FEDCBA987654321, 0x0000000000000000, 0xFFFFFFFFFFFFFFFF];
/// let bytes = u256_to_be_bytes32(&limbs);
/// // limbs[0] occupies bytes[0..8], limbs[3] occupies bytes[24..32]
/// assert_eq!(&bytes[0..8], &limbs[0].to_be_bytes());
/// assert_eq!(&bytes[24..32], &limbs[3].to_be_bytes());
/// ```
pub(crate) fn u256_to_be_bytes32(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
}

/// Compare two 256-bit values represented as four big-endian u64 limbs.
///
/// The comparison is lexicographic from the most-significant limb (index 0)
/// to the least-significant limb (index 3).
///
/// # Examples
///
/// ```
/// let a = [0u64, 0, 0, 1];
/// let b = [0u64, 0, 0, 2];
/// assert_eq!(u256_cmp(&a, &b), core::cmp::Ordering::Less);
/// ```
fn u256_cmp(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
    for i in 0..4 {
        if a[i] < b[i] {
            return core::cmp::Ordering::Less;
        }
        if a[i] > b[i] {
            return core::cmp::Ordering::Greater;
        }
    }
    core::cmp::Ordering::Equal
}

/// Checks whether a 256-bit value represented as four 64-bit limbs is zero.
///
/// # Returns
///
/// `true` if all four limbs are zero, `false` otherwise.
///
/// # Examples
///
/// ```
/// let zero = [0u64; 4];
/// let nonzero = [0u64, 0, 0, 1];
/// assert!(u256_is_zero(&zero));
/// assert!(!u256_is_zero(&nonzero));
/// ```
fn u256_is_zero(a: &[u64; 4]) -> bool {
    a.iter().all(|v| *v == 0)
}

/// Performs a logical right shift by 2 bits on a 256-bit value represented as four big-endian u64 limbs.
///
/// The input is interpreted as a big-endian 4-limb representation (index 0 = most significant limb).
///
/// # Returns
///
/// The shifted 256-bit value as four big-endian `u64` limbs.
///
/// # Examples
///
/// ```
/// let a = [0u64, 0, 0, 4]; // 4 in the least-significant limb
/// let s = u256_shr2(&a);
/// assert_eq!(s, [0u64, 0, 0, 1]);
/// ```
fn u256_shr2(a: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry: u64 = 0;
    for i in 0..4 {
        let v = a[i];
        out[i] = (carry << 62) | (v >> 2);
        carry = v & 0x3;
    }
    out
}

/// Performs a saturating left shift by 2 bits on a 256-bit value represented as four big-endian 64-bit limbs.
///
/// The input `a` is interpreted as a big-endian 4-limb 256-bit integer (index 0 = most-significant limb).
/// The result is the value shifted left by 2 bits with carries propagated across limbs. If any bits are
/// lost by shifting out past the most-significant limb, the function returns `MAX_TARGET` (via `u256_from_be_bytes32`)
/// instead of wrapping.
///
/// # Examples
///
/// ```
/// // 1 << 2 == 4
/// let in_limbs = [0u64, 0, 0, 1];
/// let out = u256_shl2_saturating(&in_limbs);
/// assert_eq!(out, [0u64, 0, 0, 4]);
/// ```
fn u256_shl2_saturating(a: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry: u64 = 0;
    for i in (0..4).rev() {
        let v = a[i];
        out[i] = (v << 2) | carry;
        carry = v >> 62;
    }
    if carry != 0 {
        return u256_from_be_bytes32(&MAX_TARGET);
    }
    out
}

/// Multiply a 256-bit value (4 big-endian 64-bit limbs) by a 64-bit scalar, returning a 320-bit result (5 big-endian 64-bit limbs).
///
/// The input `a` is interpreted as a big-endian 4-limb unsigned integer and the result is returned as a big-endian 5-limb array to hold any overflow.
///
/// # Examples
///
/// ```
/// let a = [0u64, 0, 0, 1]; // represents 1
/// let res = u256_mul_u64_to_u320(&a, 2);
/// assert_eq!(res, [0u64, 0, 0, 0, 2]); // represents 2
/// ```
fn u256_mul_u64_to_u320(a: &[u64; 4], m: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for i in (0..4).rev() {
        let prod = (a[i] as u128) * (m as u128) + carry;
        out[i + 1] = (prod & 0xffff_ffff_ffff_ffff) as u64;
        carry = prod >> 64;
    }
    out[0] = carry as u64;
    out
}

/// Divide a 5-limb (320-bit) unsigned value by a 64-bit divisor and return the 4-limb (256-bit) quotient.
///
/// The input `n` is interpreted as a big-endian sequence of five 64-bit limbs (most-significant limb first).
/// If `d` is zero, returns `Err(BLOCK_ERR_TARGET_INVALID)`. If the division would produce a non-zero
/// most-significant quotient limb (i.e., the result does not fit in 256 bits), the function returns
/// `Ok(MAX_TARGET)` as a saturated/clamped result.
///
/// # Parameters
///
/// - `n`: five 64-bit limbs representing a 320-bit unsigned integer in big-endian order.
/// - `d`: 64-bit divisor.
///
/// # Returns
///
/// `Ok([u64; 4])` with the 256-bit quotient in big-endian limb order, or `Err(String)` when `d == 0`.
///
/// # Examples
///
/// ```
/// // divide a small 320-bit value (10) by 2 -> quotient is 5
/// let n = [0u64, 0, 0, 0, 10];
/// let q = u320_div_u64_to_u256(&n, 2).unwrap();
/// assert_eq!(q, [0u64, 0, 0, 5]);
/// ```
fn u320_div_u64_to_u256(n: &[u64; 5], d: u64) -> Result<[u64; 4], String> {
    if d == 0 {
        return Err(BLOCK_ERR_TARGET_INVALID.into());
    }
    let mut q = [0u64; 4];
    let mut rem: u128 = 0;
    for i in 0..5 {
        let limb = n[i] as u128;
        let cur = (rem << 64) | limb;
        let q_limb = cur / (d as u128);
        rem = cur % (d as u128);
        if i > 0 {
            q[i - 1] = q_limb as u64;
        } else if q_limb != 0 {
            return Ok(u256_from_be_bytes32(&MAX_TARGET));
        }
    }
    Ok(q)
}

/// Compute the expected PoW target for `height` using the past `headers` and the consensus difficulty window.
///
/// Returns `target_in` unchanged when `height == 0`. When `height` is not a multiple of the difficulty
/// adjustment window the most-recent header target is returned. For difficulty-adjustment heights the
/// function scales the last header target by the ratio of actual to expected time over the window,
/// then clamps the result to be within one quarter (right shift by 2) and four times (saturating left
/// shift by 2) of the previous target.
///
/// # Errors
///
/// Returns `Err(BLOCK_ERR_TARGET_INVALID)` when `headers` is empty or contains fewer entries than the
/// required window for adjustment, or when an internal division-by-zero or invalid intermediate state
/// is encountered.
///
/// # Examples
///
/// ```
/// // height 0 returns the provided input target unchanged
/// let hdrs: &[crate::pow::BlockHeader] = &[];
/// let t_in = [0u8; 32];
/// let res = crate::pow::block_expected_target(hdrs, 0, &t_in).unwrap();
/// assert_eq!(res, t_in);
/// ```
pub(crate) fn block_expected_target(
    headers: &[BlockHeader],
    height: u64,
    target_in: &[u8; 32],
) -> Result<[u8; 32], String> {
    if height == 0 {
        return Ok(*target_in);
    }
    if headers.is_empty() {
        return Err(BLOCK_ERR_TARGET_INVALID.into());
    }

    let target_old = u256_from_be_bytes32(&headers[headers.len() - 1].target);
    if !height.is_multiple_of(WINDOW_SIZE) {
        return Ok(u256_to_be_bytes32(&target_old));
    }

    let window = WINDOW_SIZE as usize;
    if headers.len() < window {
        return Err(BLOCK_ERR_TARGET_INVALID.into());
    }

    let first_ts = headers[headers.len() - window].timestamp;
    let last_ts = headers[headers.len() - 1].timestamp;
    let t_actual = if last_ts >= first_ts {
        last_ts - first_ts
    } else {
        1
    };
    let t_expected = TARGET_BLOCK_INTERVAL * WINDOW_SIZE;

    let n320 = u256_mul_u64_to_u320(&target_old, t_actual);
    let mut target_new = u320_div_u64_to_u256(&n320, t_expected)?;

    let mut min_target = u256_shr2(&target_old);
    if u256_is_zero(&min_target) {
        min_target = [0, 0, 0, 1];
    }
    let max_target = u256_shl2_saturating(&target_old);

    if u256_cmp(&target_new, &min_target) == core::cmp::Ordering::Less {
        target_new = min_target;
    }
    if u256_cmp(&target_new, &max_target) == core::cmp::Ordering::Greater {
        target_new = max_target;
    }

    Ok(u256_to_be_bytes32(&target_new))
}