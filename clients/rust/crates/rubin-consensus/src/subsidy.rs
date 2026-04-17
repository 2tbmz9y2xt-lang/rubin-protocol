use crate::constants::{EMISSION_SPEED_FACTOR, MINEABLE_CAP, TAIL_EMISSION_PER_BLOCK};

// block_subsidy(h) per CANONICAL §19.1.
//
// already_generated is already_generated(h): sum of subsidy-only (excluding fees) for coinbase
// transactions in heights 1..h-1.
//
// Deriving already_generated from chain state is the caller's responsibility.
pub fn block_subsidy(height: u64, already_generated: u128) -> u64 {
    if height == 0 {
        return 0;
    }
    let mineable_cap = u128::from(MINEABLE_CAP);
    if already_generated >= mineable_cap {
        return TAIL_EMISSION_PER_BLOCK;
    }
    let remaining = mineable_cap - already_generated;
    let base_reward = remaining >> EMISSION_SPEED_FACTOR;
    if base_reward < u128::from(TAIL_EMISSION_PER_BLOCK) {
        return TAIL_EMISSION_PER_BLOCK;
    }
    clamp_base_reward_to_u64(base_reward)
}

/// Narrow `base_reward` from the u128 subsidy arithmetic into `u64` with
/// an explicit overflow guard — the Rust equivalent of Go's
/// `baseReward.IsUint64()` check (clients/go/consensus/subsidy.go:43-47).
///
/// Unreachable for current constants (MINEABLE_CAP fits in u64 and the
/// right shift by EMISSION_SPEED_FACTOR only reduces the value), but
/// the guard preserves deterministic behavior for malformed caller
/// state and prevents silent truncation via `as u64`.
fn clamp_base_reward_to_u64(base_reward: u128) -> u64 {
    match u64::try_from(base_reward) {
        Ok(v) => v,
        Err(_) => TAIL_EMISSION_PER_BLOCK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_subsidy_height_zero_is_zero() {
        assert_eq!(block_subsidy(0, 0), 0);
        assert_eq!(block_subsidy(0, u128::MAX), 0);
    }

    #[test]
    fn block_subsidy_height_one_matches_spec_formula() {
        assert_eq!(block_subsidy(1, 0), 4_673_004_150);
    }

    #[test]
    fn block_subsidy_returns_tail_at_and_above_cap() {
        let mineable_cap = u128::from(MINEABLE_CAP);
        assert_eq!(block_subsidy(1, mineable_cap), TAIL_EMISSION_PER_BLOCK);
        assert_eq!(block_subsidy(1, mineable_cap + 1), TAIL_EMISSION_PER_BLOCK);
    }

    #[test]
    fn block_subsidy_clamps_to_tail_when_base_reward_would_undercut() {
        let remaining_below_tail = u128::from(TAIL_EMISSION_PER_BLOCK - 1) << EMISSION_SPEED_FACTOR;
        let already_generated = u128::from(MINEABLE_CAP) - remaining_below_tail;
        assert_eq!(block_subsidy(1, already_generated), TAIL_EMISSION_PER_BLOCK);
    }

    #[test]
    fn block_subsidy_uses_base_reward_formula_when_above_tail() {
        let already_generated = 123u128;
        let expected =
            ((u128::from(MINEABLE_CAP) - already_generated) >> EMISSION_SPEED_FACTOR) as u64;
        assert_eq!(block_subsidy(1, already_generated), expected);
    }

    #[test]
    fn block_subsidy_positive_height_never_undercuts_tail() {
        assert!(block_subsidy(1, 0) >= TAIL_EMISSION_PER_BLOCK);
        assert!(block_subsidy(u64::MAX, u128::from(MINEABLE_CAP) - 1) >= TAIL_EMISSION_PER_BLOCK);
    }

    #[test]
    fn clamp_base_reward_within_u64_passes_through() {
        // Values that fit u64 go through unchanged.
        assert_eq!(clamp_base_reward_to_u64(0), 0);
        assert_eq!(clamp_base_reward_to_u64(1), 1);
        assert_eq!(clamp_base_reward_to_u64(u128::from(u64::MAX)), u64::MAX);
        assert_eq!(
            clamp_base_reward_to_u64(u128::from(TAIL_EMISSION_PER_BLOCK)),
            TAIL_EMISSION_PER_BLOCK
        );
    }

    #[test]
    fn clamp_base_reward_overflow_falls_back_to_tail() {
        // Overflow branch matches Go `BlockSubsidyBig` `IsUint64()` behavior:
        // deterministic fallback to TAIL_EMISSION_PER_BLOCK (not a silent
        // truncation via `as u64`).  Unreachable for current constants but
        // verifies the guard exists and fires.
        assert_eq!(
            clamp_base_reward_to_u64(u128::from(u64::MAX) + 1),
            TAIL_EMISSION_PER_BLOCK
        );
        assert_eq!(clamp_base_reward_to_u64(u128::MAX), TAIL_EMISSION_PER_BLOCK);
    }

    #[test]
    fn block_subsidy_repeat_is_deterministic() {
        let height = 42;
        let already_generated = 123_456_789u128;
        assert_eq!(
            block_subsidy(height, already_generated),
            block_subsidy(height, already_generated)
        );
    }
}

// ---------------------------------------------------------------------------
// Kani bounded model checking proofs
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod verification {
    use super::*;

    /// block_subsidy never panics for any (height, already_generated) pair.
    #[kani::proof]
    fn verify_subsidy_no_panic() {
        let height: u64 = kani::any();
        let already_generated: u128 = kani::any();
        let _ = block_subsidy(height, already_generated);
    }

    /// block_subsidy always returns >= TAIL_EMISSION_PER_BLOCK for height > 0.
    #[kani::proof]
    fn verify_subsidy_floor() {
        let height: u64 = kani::any();
        kani::assume(height > 0);
        let already_generated: u128 = kani::any();
        let subsidy = block_subsidy(height, already_generated);
        assert!(subsidy >= TAIL_EMISSION_PER_BLOCK);
    }

    /// block_subsidy(0, _) is always 0 (genesis has no subsidy).
    #[kani::proof]
    fn verify_subsidy_genesis_zero() {
        let already_generated: u128 = kani::any();
        assert_eq!(block_subsidy(0, already_generated), 0);
    }

    /// `clamp_base_reward_to_u64` never panics, and its result is
    /// either the input unchanged (when it fits u64) or the
    /// deterministic `TAIL_EMISSION_PER_BLOCK` fallback (matching Go's
    /// `IsUint64()` branch).  No silent truncation via `as u64`.
    #[kani::proof]
    fn verify_clamp_base_reward_no_overflow() {
        let base_reward: u128 = kani::any();
        let clamped = clamp_base_reward_to_u64(base_reward);
        if base_reward <= u128::from(u64::MAX) {
            // Fits u64 — identity.
            assert_eq!(u128::from(clamped), base_reward);
        } else {
            // Overflow — deterministic tail fallback.
            assert_eq!(clamped, TAIL_EMISSION_PER_BLOCK);
        }
    }
}
