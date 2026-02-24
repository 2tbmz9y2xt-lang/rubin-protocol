use crate::constants::{EMISSION_SPEED_FACTOR, MINEABLE_CAP, TAIL_EMISSION_PER_BLOCK};

// block_subsidy(h) per CANONICAL §19.1.
//
// already_generated is already_generated(h): sum of subsidy-only (excluding fees) for coinbase
// transactions in heights 1..h-1.
//
// Deriving already_generated from chain state is the caller's responsibility.
pub fn block_subsidy(height: u64, already_generated: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    if already_generated >= MINEABLE_CAP {
        return TAIL_EMISSION_PER_BLOCK;
    }
    let remaining = MINEABLE_CAP - already_generated;
    let base_reward = remaining >> EMISSION_SPEED_FACTOR;
    if base_reward < TAIL_EMISSION_PER_BLOCK {
        TAIL_EMISSION_PER_BLOCK
    } else {
        base_reward
    }
}
