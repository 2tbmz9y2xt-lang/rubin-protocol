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
        TAIL_EMISSION_PER_BLOCK
    } else {
        base_reward as u64
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
}
