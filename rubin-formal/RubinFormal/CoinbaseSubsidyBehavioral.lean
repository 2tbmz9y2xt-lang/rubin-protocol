import RubinFormal.SubsidyV1

/-!
# Coinbase Subsidy Behavioral Proofs (§19)
-/

namespace RubinFormal
open SubsidyV1

/-- Genesis block (height 0) has zero subsidy. -/
theorem subsidy_genesis_zero : blockSubsidy 0 0 = 0 := by rfl

/-- After mineable cap, subsidy = tail emission. -/
theorem subsidy_at_cap :
    blockSubsidy 1 MINEABLE_CAP = TAIL_EMISSION_PER_BLOCK := by rfl

/-- Tail emission value. -/
theorem tail_emission_value : TAIL_EMISSION_PER_BLOCK = 19025875 := rfl

/-- Subsidy at height 1 with zero generated is positive. -/
theorem subsidy_height1_positive :
    blockSubsidy 1 0 > 0 := by native_decide

end RubinFormal
