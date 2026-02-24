package consensus

// BlockSubsidy computes block_subsidy(h) per CANONICAL §19.1.
//
// alreadyGenerated is already_generated(h): the sum of subsidy-only (excluding fees)
// for coinbase transactions in heights 1..h-1.
//
// This function is consensus-critical, but note: deriving alreadyGenerated from chain state
// is the caller's responsibility.
func BlockSubsidy(height uint64, alreadyGenerated uint64) uint64 {
	if height == 0 {
		return 0
	}
	if alreadyGenerated >= MINEABLE_CAP {
		return TAIL_EMISSION_PER_BLOCK
	}
	remaining := MINEABLE_CAP - alreadyGenerated
	baseReward := remaining >> EMISSION_SPEED_FACTOR
	if baseReward < TAIL_EMISSION_PER_BLOCK {
		return TAIL_EMISSION_PER_BLOCK
	}
	return baseReward
}
