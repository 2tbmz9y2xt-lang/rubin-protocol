use crate::encode::block_header_bytes;
use crate::{
    BLOCK_ERR_TARGET_INVALID, BLOCK_ERR_TIMESTAMP_OLD, BlockHeader, MAX_TARGET,
    TARGET_BLOCK_INTERVAL, WINDOW_SIZE,
};
use rubin_crypto::CryptoProvider;

pub fn block_header_hash(
    provider: &dyn CryptoProvider,
    h: &BlockHeader,
) -> Result<[u8; 32], String> {
    provider.sha3_256(&block_header_bytes(h))
}

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

#[allow(clippy::needless_range_loop)]
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

pub(crate) fn u256_to_be_bytes32(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
}

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

fn u256_is_zero(a: &[u64; 4]) -> bool {
    a.iter().all(|v| *v == 0)
}

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
