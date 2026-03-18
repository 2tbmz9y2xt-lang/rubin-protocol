/-
  CoreExtRefinement.lean — Formal refinement for CORE_EXT deterministic branches.

  Q-FORMAL-CORE-EXT-01: Proves properties about CORE_EXT activation
  transitions, deterministic error-priority mapping, and duplicate
  ACTIVE profile rejection. Maps back to CV-EXT-* fixture families.
-/
import RubinFormal.CriticalInvariants

namespace RubinFormal.CoreExtRefinement

open RubinFormal

-- ============================================================================
-- Section 1: Activation State Machine
-- ============================================================================

/-- CORE_EXT profile activation state at a given height. -/
inductive ActivationState
  | PreActive    -- height < activation_height: permissive path
  | Active       -- height >= activation_height: enforcement path
deriving DecidableEq

/-- Determine activation state from height and activation_height. -/
def activationStateAt (height activationHeight : Nat) : ActivationState :=
  if height < activationHeight then ActivationState.PreActive
  else ActivationState.Active

/-- At activation height, state is Active. -/
theorem active_at_activation (activationHeight : Nat) :
    activationStateAt activationHeight activationHeight = ActivationState.Active := by
  simp only [activationStateAt]
  split
  · rename_i h; omega
  · rfl

/-- Before activation height (h > 0), state is PreActive. -/
theorem pre_active_before (activationHeight : Nat) (hPos : 0 < activationHeight) :
    activationStateAt (activationHeight - 1) activationHeight = ActivationState.PreActive := by
  simp only [activationStateAt]
  split
  · rfl
  · rename_i h; omega

/-- Activation is monotone: once Active, stays Active. -/
theorem activation_monotone (h1 h2 activationHeight : Nat)
    (hLe : h1 ≤ h2)
    (hActive : activationStateAt h1 activationHeight = ActivationState.Active) :
    activationStateAt h2 activationHeight = ActivationState.Active := by
  simp only [activationStateAt] at *
  split at hActive
  · contradiction
  · split
    · rename_i h2lt h1ge; omega
    · rfl

/-- Genesis-active profile (activation_height = 0) is Active at height 0. -/
theorem genesis_active_at_zero :
    activationStateAt 0 0 = ActivationState.Active := by
  simp [activationStateAt]

-- ============================================================================
-- Section 2: Deterministic Error Priority
-- ============================================================================

/-- CORE_EXT error codes in priority order. -/
inductive ExtError
  | ParseError       -- TX_ERR_COVENANT_TYPE_INVALID (envelope malformed)
  | SuiteDisallowed  -- TX_ERR_SIG_ALG_INVALID (suite not in allowed set)
  | SigInvalid       -- TX_ERR_SIG_INVALID (signature verification failed)
deriving DecidableEq

/-- Error priority: ParseError > SuiteDisallowed > SigInvalid.
    Parse errors are detected before suite checks, which are
    detected before signature verification. -/
def errorPriority : ExtError → Nat
  | ExtError.ParseError => 0
  | ExtError.SuiteDisallowed => 1
  | ExtError.SigInvalid => 2

/-- Parse errors always have higher priority than suite errors. -/
theorem parse_before_suite :
    errorPriority ExtError.ParseError < errorPriority ExtError.SuiteDisallowed := by
  native_decide

/-- Suite errors always have higher priority than sig errors. -/
theorem suite_before_sig :
    errorPriority ExtError.SuiteDisallowed < errorPriority ExtError.SigInvalid := by
  native_decide

/-- Given two errors, the deterministic winner is the one with lower priority number. -/
def deterministicError (e1 e2 : ExtError) : ExtError :=
  if errorPriority e1 ≤ errorPriority e2 then e1 else e2

/-- Deterministic error selection is commutative. -/
theorem error_selection_commutative (e1 e2 : ExtError) :
    deterministicError e1 e2 = deterministicError e2 e1 := by
  cases e1 <;> cases e2 <;> simp [deterministicError, errorPriority]

/-- If a parse error is present, it always wins. -/
theorem parse_always_wins (e : ExtError) :
    deterministicError ExtError.ParseError e = ExtError.ParseError := by
  cases e <;> simp [deterministicError, errorPriority]

-- ============================================================================
-- Section 3: Duplicate ACTIVE Profile Rejection
-- ============================================================================

/-- A deployment profile record. -/
structure DeploymentProfile where
  extId : Nat
  activationHeight : Nat

/-- Check for duplicate ext_ids in a list of profiles. -/
def hasDuplicateExtId : List DeploymentProfile → Bool
  | [] => false
  | p :: rest =>
    if rest.any (fun q => q.extId == p.extId) then true
    else hasDuplicateExtId rest

/-- Empty profile list has no duplicates (definitional). -/
theorem no_duplicates_empty : hasDuplicateExtId [] = false := rfl

/-- A single profile has no duplicates (definitional). -/
theorem no_duplicates_singleton (p : DeploymentProfile) :
    hasDuplicateExtId [p] = false := by
  simp [hasDuplicateExtId, List.any]

/-- Concrete 3-profile list with distinct ext_ids: no duplicates. -/
theorem no_duplicates_three_distinct :
    hasDuplicateExtId [
      { extId := 1, activationHeight := 10 },
      { extId := 2, activationHeight := 20 },
      { extId := 3, activationHeight := 30 }
    ] = false := by native_decide

/-- Concrete 3-profile list with a duplicate: detected. -/
theorem duplicate_in_three :
    hasDuplicateExtId [
      { extId := 1, activationHeight := 10 },
      { extId := 2, activationHeight := 20 },
      { extId := 1, activationHeight := 30 }
    ] = true := by native_decide

/-- Two profiles with the same ext_id are detected as duplicates. -/
theorem duplicate_detected (p q : DeploymentProfile) (h : p.extId = q.extId) :
    hasDuplicateExtId [p, q] = true := by
  simp [hasDuplicateExtId, List.any, BEq.beq, h]

/-- Two profiles with different ext_ids are not duplicates. -/
theorem no_duplicate_different_ids (p q : DeploymentProfile) (h : p.extId ≠ q.extId) :
    hasDuplicateExtId [p, q] = false := by
  simp [hasDuplicateExtId, List.any]
  intro heq
  exact absurd heq.symm h

-- ============================================================================
-- Section 4: Suite Authorization
-- ============================================================================

/-- Check if a suite ID is in the allowed set. -/
def suiteAllowed (suiteId : Nat) (allowedSuites : List Nat) : Bool :=
  allowedSuites.contains suiteId

/-- Keyless sentinel (suite_id = 0): when 0 is in the allowed list,
    suiteAllowed returns true. Models the sentinel bypass rule. -/
theorem keyless_sentinel_in_allowed :
    suiteAllowed 0 [0, 1, 3] = true := by native_decide

/-- When suite_id is NOT in the allowed list, suiteAllowed returns false. -/
theorem suite_not_allowed_when_absent :
    suiteAllowed 5 [1, 3] = false := by native_decide

/-- Suite authorization is deterministic: same inputs produce same result. -/
theorem suite_auth_deterministic (s : Nat) (allowed : List Nat) :
    suiteAllowed s allowed = suiteAllowed s allowed := rfl

/-- Concrete: suite 1 is allowed in [1, 3]. -/
theorem suite_1_in_1_3 : suiteAllowed 1 [1, 3] = true := by native_decide

/-- Concrete: suite 2 is NOT allowed in [1, 3]. -/
theorem suite_2_not_in_1_3 : suiteAllowed 2 [1, 3] = false := by native_decide

/-- Empty allowed list rejects everything. -/
theorem suite_empty_rejects : suiteAllowed 1 [] = false := by native_decide

-- ============================================================================
-- Section 5: Pre-Activation Permissive Path
-- ============================================================================

/-- Model CORE_EXT spend decision: if profile not active → permissive (true),
    if active → check suite membership. -/
def extSpendDecision (profileActive : Bool) (suiteId : Nat) (allowedSuites : List Nat) : Bool :=
  if !profileActive then true
  else suiteAllowed suiteId allowedSuites

/-- Pre-activation (profileActive = false): unconditionally permissive
    regardless of suite_id or allowed list contents. -/
theorem pre_activation_always_accepts (suiteId : Nat) (allowed : List Nat) :
    extSpendDecision false suiteId allowed = true := by
  simp [extSpendDecision]

/-- Pre-activation result is independent of suite_id: two different
    suites get the same (accept) result when profile is inactive. -/
theorem pre_activation_suite_independent (s1 s2 : Nat) (allowed : List Nat) :
    extSpendDecision false s1 allowed = extSpendDecision false s2 allowed := by
  simp [extSpendDecision]

/-- Post-activation with disallowed suite → reject. This is the
    non-trivial counterpart: enforcement actually rejects. -/
theorem post_activation_disallowed_rejects :
    extSpendDecision true 5 [1, 3] = false := by native_decide

/-- Post-activation with allowed suite → accept. -/
theorem post_activation_allowed_accepts :
    extSpendDecision true 3 [1, 3] = true := by native_decide

end RubinFormal.CoreExtRefinement
