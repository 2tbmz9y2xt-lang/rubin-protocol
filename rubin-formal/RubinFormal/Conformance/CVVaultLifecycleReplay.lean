import RubinFormal.VaultStateMachine

namespace RubinFormal.Conformance

open RubinFormal

/-- Full happy-path lifecycle: created → triggered → swept.
    Valid whenever the HTLC timelock condition is satisfied. -/
theorem vault_full_lifecycle_valid
    (lockMode lockValue blockHeight blockMtp : Nat)
    (hMode : lockMode <= CovenantGenesisV1.LOCK_MODE_TIMESTAMP)
    (hPositive : 0 < lockValue)
    (hTimelock : CovenantGenesisV1.htlcTimelockMet lockMode lockValue blockHeight blockMtp = true) :
    vaultTransition .created .trigger = some .triggered ∧
    vaultTransition .triggered (.sweep lockMode lockValue blockHeight blockMtp) = some .swept := by
  constructor
  · rfl
  · simp [vaultTransition, validSweepParams, hMode, hPositive, hTimelock]

/-- Cancel lifecycle: created → cancelled, and cancelled blocks sweep. -/
theorem vault_cancel_lifecycle_valid :
    vaultTransition .created .cancel = some .cancelled ∧
    ∀ lm lv bh bm : Nat, vaultTransition .cancelled (.sweep lm lv bh bm) = none := by
  constructor
  · rfl
  · intros; rfl

end RubinFormal.Conformance
