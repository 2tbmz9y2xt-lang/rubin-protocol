import RubinFormal.Types

/-!
# Feature Activation FSM (CANONICAL §23)

Formal model of the FeatureBit signaling state machine and FlagDay
height-activation used by the live Go/Rust helpers.

Live code mapping:
- Go: consensus/featurebits.go → evalFeatureBitsNextState
- Rust: rubin-consensus/src/featurebits.rs → next_state
- Go: consensus/flagday.go → FlagDayActiveAtHeight
- Rust: rubin-consensus/src/flagday.rs → flagday_active_at_height
-/

namespace RubinFormal

inductive FeatureBitState where
  | defined
  | started
  | lockedIn
  | active
  | failed
  deriving DecidableEq, Repr

structure FeatureBitDeployment where
  startHeight : Nat
  timeoutHeight : Nat
  deriving DecidableEq, Repr

def SIGNAL_THRESHOLD : Nat := 1815

def featureBitNextState
    (prev : FeatureBitState)
    (boundaryHeight prevWindowSignalCount : Nat)
    (d : FeatureBitDeployment) : FeatureBitState :=
  match prev with
  | .defined =>
      if boundaryHeight >= d.startHeight then .started
      else .defined
  | .started =>
      if prevWindowSignalCount >= SIGNAL_THRESHOLD then .lockedIn
      else if boundaryHeight >= d.timeoutHeight then .failed
      else .started
  | .lockedIn => .active
  | .active => .active
  | .failed => .failed

theorem active_terminal (bh cnt : Nat) (d : FeatureBitDeployment) :
    featureBitNextState .active bh cnt d = .active := rfl

theorem failed_terminal (bh cnt : Nat) (d : FeatureBitDeployment) :
    featureBitNextState .failed bh cnt d = .failed := rfl

theorem locked_in_always_activates (bh cnt : Nat) (d : FeatureBitDeployment) :
    featureBitNextState .lockedIn bh cnt d = .active := rfl

def featureBitStateOrd : FeatureBitState → Nat
  | .defined  => 0
  | .started  => 1
  | .lockedIn => 2
  | .active   => 3
  | .failed   => 3

theorem state_order_monotone
    (prev : FeatureBitState) (bh cnt : Nat)
    (d : FeatureBitDeployment) :
    featureBitStateOrd prev ≤
    featureBitStateOrd (featureBitNextState prev bh cnt d) := by
  cases prev
  case defined =>
    show 0 ≤ featureBitStateOrd (if bh ≥ d.startHeight then .started else .defined)
    split <;> decide
  case started =>
    show 1 ≤ featureBitStateOrd
      (if cnt ≥ SIGNAL_THRESHOLD then .lockedIn
       else if bh ≥ d.timeoutHeight then .failed else .started)
    split
    · decide
    · split <;> decide
  case lockedIn => simp [featureBitNextState, featureBitStateOrd]
  case active => simp [featureBitNextState, featureBitStateOrd]
  case failed => simp [featureBitNextState, featureBitStateOrd]

theorem multi_step_monotone
    (d : FeatureBitDeployment)
    (init : FeatureBitState)
    (windows : List (Nat × Nat)) :
    featureBitStateOrd init ≤
    featureBitStateOrd (windows.foldl
      (fun s p => featureBitNextState s p.1 p.2 d) init) := by
  induction windows generalizing init with
  | nil => exact Nat.le_refl _
  | cons w ws ih =>
    simp only [List.foldl]
    exact Nat.le_trans
      (state_order_monotone init w.1 w.2 d)
      (ih (featureBitNextState init w.1 w.2 d))

theorem active_persists_multi_step
    (d : FeatureBitDeployment)
    (windows : List (Nat × Nat)) :
    windows.foldl (fun s p => featureBitNextState s p.1 p.2 d)
      .active = .active := by
  induction windows with
  | nil => rfl
  | cons _ ws ih =>
    simp only [List.foldl, active_terminal]; exact ih

theorem failed_persists_multi_step
    (d : FeatureBitDeployment)
    (windows : List (Nat × Nat)) :
    windows.foldl (fun s p => featureBitNextState s p.1 p.2 d)
      .failed = .failed := by
  induction windows with
  | nil => rfl
  | cons _ ws ih =>
    simp only [List.foldl, failed_terminal]; exact ih

theorem defined_next_cases (bh cnt : Nat) (d : FeatureBitDeployment) :
    featureBitNextState .defined bh cnt d = .defined ∨
    featureBitNextState .defined bh cnt d = .started := by
  show (if bh ≥ d.startHeight then FeatureBitState.started
        else .defined) = .defined ∨
       (if bh ≥ d.startHeight then FeatureBitState.started
        else .defined) = .started
  split
  · exact Or.inr rfl
  · exact Or.inl rfl

theorem started_next_cases (bh cnt : Nat) (d : FeatureBitDeployment) :
    featureBitNextState .started bh cnt d = .started ∨
    featureBitNextState .started bh cnt d = .lockedIn ∨
    featureBitNextState .started bh cnt d = .failed := by
  show (if cnt ≥ SIGNAL_THRESHOLD then FeatureBitState.lockedIn
        else if bh ≥ d.timeoutHeight then .failed
        else .started) = .started ∨
       (if cnt ≥ SIGNAL_THRESHOLD then FeatureBitState.lockedIn
        else if bh ≥ d.timeoutHeight then .failed
        else .started) = .lockedIn ∨
       (if cnt ≥ SIGNAL_THRESHOLD then FeatureBitState.lockedIn
        else if bh ≥ d.timeoutHeight then .failed
        else .started) = .failed
  split
  · exact Or.inr (Or.inl rfl)
  · split
    · exact Or.inr (Or.inr rfl)
    · exact Or.inl rfl

def flagDayActive (activationHeight height : Nat) : Bool :=
  height ≥ activationHeight

theorem flagday_monotone
    (activationHeight h h' : Nat)
    (hLe : h ≤ h')
    (hActive : flagDayActive activationHeight h = true) :
    flagDayActive activationHeight h' = true := by
  simp [flagDayActive] at *
  omega

theorem flagday_boundary (activationHeight h : Nat)
    (hLt : h < activationHeight) :
    flagDayActive activationHeight h = false := by
  simp [flagDayActive]
  omega

theorem flagday_exact_activation (activationHeight : Nat) :
    flagDayActive activationHeight activationHeight = true := by
  simp [flagDayActive]

end RubinFormal
