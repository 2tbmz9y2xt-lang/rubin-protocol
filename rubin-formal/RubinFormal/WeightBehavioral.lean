import RubinFormal.CriticalInvariants

/-!
# Weight Accounting Behavioral Proofs (§9)

Proves behavioral properties of the canonical weight decomposition:
`weight(base, witness, sigCost) = base * 4 + witness + sigCost`
-/

namespace RubinFormal

-- weight is defined in RubinFormal namespace in CriticalInvariants.lean

/-- Weight decomposition is additive: adding to any component
    increases weight by exactly that amount. -/
theorem weight_add_base (base delta witness sigCost : Nat) :
    weight (base + delta) witness sigCost =
    weight base witness sigCost + delta * 4 := by
  simp [weight, Nat.add_mul, Nat.add_assoc, Nat.add_comm (delta * 4)]

theorem weight_add_witness (base witness delta sigCost : Nat) :
    weight base (witness + delta) sigCost =
    weight base witness sigCost + delta := by
  simp [weight]; omega

theorem weight_add_sigCost (base witness sigCost delta : Nat) :
    weight base witness (sigCost + delta) =
    weight base witness sigCost + delta := by
  simp [weight, Nat.add_assoc]

/-- Weight is zero only when all components are zero. -/
theorem weight_zero_iff (base witness sigCost : Nat) :
    weight base witness sigCost = 0 ↔ base = 0 ∧ witness = 0 ∧ sigCost = 0 := by
  simp [weight]
  omega

/-- Weight with all-zero components is zero. -/
theorem weight_zero : weight 0 0 0 = 0 := rfl

/-- Base has 4x scaling — this is the segregated witness discount factor. -/
theorem weight_base_scaling (n : Nat) :
    weight n 0 0 = n * 4 := by
  simp [weight]

end RubinFormal
