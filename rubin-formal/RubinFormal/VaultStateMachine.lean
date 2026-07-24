import RubinFormal.CovenantGenesisV1
import RubinFormal.Conformance.CVVaultPolicyReplay

namespace RubinFormal

/-- Policy-level lifecycle for a `CORE_VAULT` output. -/
inductive VaultState where
  | created
  | triggered
  | swept
  | cancelled
  deriving DecidableEq, Repr

/-- Lifecycle actions. `wait` is an explicit stutter step so every state
    admits at least one valid transition in the model. -/
inductive VaultAction where
  | trigger
  | sweep (lockMode lockValue blockHeight blockMtp : Nat)
  | cancel
  | wait
  deriving DecidableEq, Repr

/-- Sweep parameters must satisfy the same wire-level bounds as the HTLC parser:
    only modes `0`/`1` are valid and `lockValue` must be positive. -/
def validSweepParams (lockMode lockValue : Nat) : Bool :=
  (lockMode <= CovenantGenesisV1.LOCK_MODE_TIMESTAMP) && (0 < lockValue)

def vaultTransition : VaultState -> VaultAction -> Option VaultState
  | .created, .trigger => some .triggered
  | .created, .cancel => some .cancelled
  | .created, .wait => some .created
  | .triggered, .sweep lockMode lockValue blockHeight blockMtp =>
      if validSweepParams lockMode lockValue then
        if CovenantGenesisV1.htlcTimelockMet lockMode lockValue blockHeight blockMtp then
          some .swept
        else
          none
      else
        none
  | .triggered, .wait => some .triggered
  | .swept, .wait => some .swept
  | .cancelled, .wait => some .cancelled
  | _, _ => none

theorem triggered_implies_sweepable
    (lockMode lockValue blockHeight blockMtp : Nat)
    (hMode : lockMode <= CovenantGenesisV1.LOCK_MODE_TIMESTAMP)
    (hValue : 0 < lockValue)
    (h : CovenantGenesisV1.htlcTimelockMet lockMode lockValue blockHeight blockMtp = true) :
    vaultTransition .triggered (.sweep lockMode lockValue blockHeight blockMtp) = some .swept := by
  simp [vaultTransition, validSweepParams, hMode, hValue, h]

theorem cancelled_implies_not_sweepable
    (lockMode lockValue blockHeight blockMtp : Nat) :
    vaultTransition .cancelled (.sweep lockMode lockValue blockHeight blockMtp) = none := by
  rfl

theorem no_dead_states : ∀ s : VaultState, ∃ a next, vaultTransition s a = some next := by
  intro s
  cases s with
  | created =>
      exact ⟨VaultAction.trigger, VaultState.triggered, rfl⟩
  | triggered =>
      exact ⟨VaultAction.wait, VaultState.triggered, rfl⟩
  | swept =>
      exact ⟨VaultAction.wait, VaultState.swept, rfl⟩
  | cancelled =>
      exact ⟨VaultAction.wait, VaultState.cancelled, rfl⟩

theorem timelock_enforced
    (lockMode lockValue blockHeight blockMtp : Nat)
    (h : CovenantGenesisV1.htlcTimelockMet lockMode lockValue blockHeight blockMtp = false) :
    vaultTransition .triggered (.sweep lockMode lockValue blockHeight blockMtp) = none := by
  simp [vaultTransition, validSweepParams, h]

end RubinFormal
