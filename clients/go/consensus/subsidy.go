package consensus

import "math/big"

// BlockSubsidy computes block_subsidy(h) per CANONICAL §19.1.
//
// alreadyGenerated is already_generated(h): the sum of subsidy-only (excluding fees)
// for coinbase transactions in heights 1..h-1.
//
// This function is consensus-critical, but note: deriving alreadyGenerated from chain state
// is the caller's responsibility.
func BlockSubsidy(height uint64, alreadyGenerated uint64) uint64 {
	return BlockSubsidyBig(height, new(big.Int).SetUint64(alreadyGenerated))
}

// BlockSubsidyBig computes block_subsidy(h) using arbitrary-precision arithmetic for
// already_generated/remaining/base_reward per CANONICAL §19.1.
func BlockSubsidyBig(height uint64, alreadyGenerated *big.Int) uint64 {
	if height == 0 {
		return 0
	}

	ag := new(big.Int)
	if alreadyGenerated != nil {
		ag.Set(alreadyGenerated)
	}
	// already_generated is unsigned by spec; clamp negative caller input to 0.
	if ag.Sign() < 0 {
		ag.SetUint64(0)
	}

	cap := new(big.Int).SetUint64(MINEABLE_CAP)
	if ag.Cmp(cap) >= 0 {
		return TAIL_EMISSION_PER_BLOCK
	}

	remaining := new(big.Int).Sub(cap, ag)
	baseReward := new(big.Int).Rsh(remaining, uint(EMISSION_SPEED_FACTOR))
	tail := new(big.Int).SetUint64(TAIL_EMISSION_PER_BLOCK)
	if baseReward.Cmp(tail) < 0 {
		return TAIL_EMISSION_PER_BLOCK
	}
	if !baseReward.IsUint64() {
		// Unreachable for current constants (remaining <= MINEABLE_CAP), but keep
		// deterministic behavior for malformed caller state.
		return TAIL_EMISSION_PER_BLOCK
	}
	return baseReward.Uint64()
}
