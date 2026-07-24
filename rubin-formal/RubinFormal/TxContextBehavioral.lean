import RubinFormal.TxContextFormal
import RubinFormal.UtxoApplyGenesisV1

/-!
# TxContext Behavioral Proof (§14 / §18)

Models behavioral properties of the TxContext bundle construction path
with REAL parameters (totalIn, totalOut, height, continuing data).
WIRED into `buildTxContextLive` / `connectBlockFullComputed`
(ConnectBlockFull.lean) — the computed path folds actual value lists and
derives gate inputs from the same TxContext input bundle.

Ext_id ordering, Uint128 comparison, K-overflow, and vault bridges are
closed here on the live TxContext helper surface.
-/

namespace RubinFormal

/-! ## TxContext bundle types (modeling Go/Rust structs) -/

/-- Maximum continuing outputs per ext_id (CANONICAL). -/
def TXCONTEXT_MAX_CONTINUING_OUTPUTS : Nat := 2

/-- TxContext output view. -/
structure TxOutputView where
  value : Nat
  extPayload : List UInt8

/-- Per-ext_id continuing output bundle with bounded metadata count and
    bounded carried outputs. -/
structure TxContextContinuing where
  count : Nat
  outputs : List TxOutputView
  hBound : count ≤ TXCONTEXT_MAX_CONTINUING_OUTPUTS
  hOutputsBound : outputs.length ≤ TXCONTEXT_MAX_CONTINUING_OUTPUTS

/-- TxContext base — immutable transaction-level context. -/
structure TxContextBase where
  totalIn : Nat
  totalOut : Nat
  height : Nat

/-- Full TxContext bundle. -/
structure TxContextBundle where
  base : TxContextBase
  continuingByExt : List (Nat × TxContextContinuing)
  continuingExtIds : List Nat

/-! ## Live helper surface for TxContext pre-activation gates -/

/-- Live ext_id insertion helper for deterministic ascending order.
    Mirrors the Go/Rust txcontext ext_id normalization path. -/
def insertExtId (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys => if x ≤ y then x :: y :: ys else y :: insertExtId x ys

/-- Live ext_id sort used by TxContext bundle construction. -/
def sortExtIds : List Nat → List Nat
  | [] => []
  | x :: xs => insertExtId x (sortExtIds xs)

/-- Live ext_id sort is definitionally aligned with the formal model sort. -/
private theorem insertExtId_eq_model (x : Nat) (ys : List Nat) :
    insertExtId x ys = TxContext.insertSorted x ys := by
  induction ys with
  | nil => rfl
  | cons y ys ih =>
      simp [insertExtId, TxContext.insertSorted, ih]

theorem sortExtIds_eq_model (xs : List Nat) :
    sortExtIds xs = TxContext.sortAscending xs := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
      simp [sortExtIds, TxContext.sortAscending, ih, insertExtId_eq_model]

/-- Deterministic ext_id order is collection-order independent on the live path. -/
theorem sortExtIds_order_independent (xs ys : List Nat)
    (hPerm : List.Perm xs ys) :
    sortExtIds xs = sortExtIds ys := by
  rw [sortExtIds_eq_model xs, sortExtIds_eq_model ys]
  exact TxContext.sortAscending_unique_output xs ys hPerm

/-- Live Uint128 comparator matching Go/Rust hi/lo limb ordering. -/
def compareUint128 (a b : TxContext.Uint128) : Bool :=
  if a.hi > b.hi then true
  else if a.hi = b.hi then decide (a.lo ≥ b.lo)
  else false

/-- Live limb comparator matches the TxContext model predicate exactly. -/
theorem compareUint128_eq_true_iff_model (a b : TxContext.Uint128) :
    compareUint128 a b = true ↔ TxContext.uint128GTE a b := by
  unfold compareUint128 TxContext.uint128GTE
  by_cases hgt : a.hi > b.hi
  · simp [hgt]
  · by_cases heq : a.hi = b.hi
    · by_cases hlo : a.lo ≥ b.lo <;> simp [hgt, heq, hlo]
    · simp [hgt, heq]

/-- Live Uint128 comparator is numerically equivalent to the native value order. -/
theorem compareUint128_native_equivalence (a b : TxContext.Uint128) :
    compareUint128 a b = true ↔ a.toNat ≥ b.toNat := by
  rw [compareUint128_eq_true_iff_model]
  exact TxContext.uint128GTE_native_equivalence a b

/-- Live K-overflow gate for continuing outputs. Mirrors the Go/Rust reject path
    before writing output index K+1. -/
def validateContinuingOutputCount (count : Nat) : Except String Unit :=
  if count > TXCONTEXT_MAX_CONTINUING_OUTPUTS then
    Except.error "TX_ERR_COVENANT_TYPE_INVALID"
  else
    Except.ok ()

/-- K-overflow rejects on the live helper surface. -/
theorem continuing_output_count_rejects_overflow (count : Nat)
    (hOverflow : count > TXCONTEXT_MAX_CONTINUING_OUTPUTS) :
    validateContinuingOutputCount count = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  simp [validateContinuingOutputCount, hOverflow]

/-- Counts within K are accepted on the live helper surface. -/
theorem continuing_output_count_accepts_in_range (count : Nat)
    (hBound : count ≤ TXCONTEXT_MAX_CONTINUING_OUTPUTS) :
    validateContinuingOutputCount count = .ok () := by
  have hNotOverflow : ¬ count > TXCONTEXT_MAX_CONTINUING_OUTPUTS := Nat.not_lt_of_ge hBound
  simp [validateContinuingOutputCount, hNotOverflow]

/-! ## BuildTxContext with real parameters -/

/-- Build TxContext bundle from real parameters.
    Models Go BuildTxContext / Rust build_tx_context.
    Takes actual totalIn, totalOut, height, and continuing data.
    Called from the aggregate compatibility wrapper in ConnectBlockFull.lean,
    AND from buildPerTxContextFromData / connectBlockFullComputed with per-tx
    resolved input/output value lists. Computed-path properties proved via
    perTx_base_values_computed and perTx_ext_ids_preserved. -/
def buildTxContext
    (activeExtIds : List Nat)
    (totalIn totalOut height : Nat)
    (continuingData : List (Nat × TxContextContinuing))
    : Option TxContextBundle :=
  if activeExtIds.length = 0 then none
  else some {
    base := { totalIn := totalIn, totalOut := totalOut, height := height }
    continuingByExt := continuingData
    continuingExtIds := sortExtIds activeExtIds
  }

/-! ## Nil/Some behavioral properties -/

/-- No active ext_ids → no bundle produced. -/
theorem buildTxContext_nil (tin tout h : Nat) (cd : List (Nat × TxContextContinuing)) :
    buildTxContext [] tin tout h cd = none := rfl

/-- Active ext_ids → bundle produced. -/
theorem buildTxContext_some (ids : List Nat) (hLen : ids.length > 0)
    (tin tout ht : Nat) (cd : List (Nat × TxContextContinuing)) :
    (buildTxContext ids tin tout ht cd).isSome = true := by
  simp only [buildTxContext]; split
  · rename_i heq; omega
  · rfl

/-! ## Structural correctness — bundle fields match inputs -/

/-- Bundle ext_ids equal the live deterministic sorted order. -/
theorem buildTxContext_ext_ids (ids : List Nat) (hLen : ids.length > 0)
    (tin tout ht : Nat) (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContext ids tin tout ht cd = some bundle) :
    bundle.continuingExtIds = sortExtIds ids := by
  simp only [buildTxContext] at hEq; split at hEq
  · rename_i heq; omega
  · cases hEq; rfl

/-- Bundle base fields reflect real parameters. -/
theorem buildTxContext_base_values (ids : List Nat) (hLen : ids.length > 0)
    (tin tout ht : Nat) (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContext ids tin tout ht cd = some bundle) :
    bundle.base.totalIn = tin ∧ bundle.base.totalOut = tout ∧ bundle.base.height = ht := by
  simp only [buildTxContext] at hEq; split at hEq
  · rename_i heq; omega
  · cases hEq; exact ⟨rfl, rfl, rfl⟩

/-- Bundle continuing data = input continuing data. -/
theorem buildTxContext_continuing_data (ids : List Nat) (hLen : ids.length > 0)
    (tin tout ht : Nat) (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContext ids tin tout ht cd = some bundle) :
    bundle.continuingByExt = cd := by
  simp only [buildTxContext] at hEq; split at hEq
  · rename_i heq; omega
  · cases hEq; rfl

/-! ## Derived properties -/

/-- No-dup preservation: if input ids are unique, bundle ids are unique. -/
theorem buildTxContext_preserves_nodup (ids : List Nat) (hLen : ids.length > 0)
    (hNodup : ids.Nodup)
    (tin tout ht : Nat) (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContext ids tin tout ht cd = some bundle) :
    bundle.continuingExtIds.Nodup := by
  rw [buildTxContext_ext_ids ids hLen tin tout ht cd bundle hEq]
  have hPerm : List.Perm ids (sortExtIds ids) := by
    rw [sortExtIds_eq_model]
    exact TxContext.sortAscending_perm ids
  exact (List.Perm.nodup_iff hPerm).mp hNodup

/-! ## Real value computation (models Go sumTxContextInputValues) -/

/-- Sum input values by folding over resolved inputs. -/
def sumInputValues (values : List Nat) : Nat := values.foldl (· + ·) 0

/-- Sum output values by folding over tx outputs. -/
def sumOutputValues (values : List Nat) : Nat := values.foldl (· + ·) 0

/-- BuildTxContext with COMPUTED totalIn/totalOut from real value lists.
    This is the REAL path: totalIn/totalOut are not free parameters
    but computed from actual input/output values via fold. -/
def buildTxContextFromValues
    (activeExtIds : List Nat)
    (inputValues outputValues : List Nat)
    (height : Nat)
    (continuingData : List (Nat × TxContextContinuing))
    : Option TxContextBundle :=
  buildTxContext activeExtIds (sumInputValues inputValues) (sumOutputValues outputValues) height continuingData

/-! ## Value conservation with REAL sums (not free parameters) -/

/-- bundle.totalIn = fold sum of actual input values. -/
theorem buildTxContextFromValues_totalIn_real
    (ids : List Nat) (hLen : ids.length > 0)
    (inVals outVals : List Nat) (ht : Nat)
    (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContextFromValues ids inVals outVals ht cd = some bundle) :
    bundle.base.totalIn = sumInputValues inVals :=
  (buildTxContext_base_values ids hLen _ _ _ cd bundle hEq).1

/-- bundle.totalOut = fold sum of actual output values. -/
theorem buildTxContextFromValues_totalOut_real
    (ids : List Nat) (hLen : ids.length > 0)
    (inVals outVals : List Nat) (ht : Nat)
    (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContextFromValues ids inVals outVals ht cd = some bundle) :
    bundle.base.totalOut = sumOutputValues outVals :=
  (buildTxContext_base_values ids hLen _ _ _ cd bundle hEq).2.1

/-- bundle.height = block height (wired through buildTxContextFromValues). -/
theorem buildTxContextFromValues_height_real
    (ids : List Nat) (hLen : ids.length > 0)
    (inVals outVals : List Nat) (blockHeight : Nat)
    (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContextFromValues ids inVals outVals blockHeight cd = some bundle) :
    bundle.base.height = blockHeight :=
  (buildTxContext_base_values ids hLen _ _ _ cd bundle hEq).2.2

/-! ## Continuing output bounds (type invariant, not precondition) -/

/-- Every TxContextContinuing carries count ≤ MAX as TYPE INVARIANT. -/
theorem continuing_bound_is_invariant (cont : TxContextContinuing) :
    cont.count ≤ TXCONTEXT_MAX_CONTINUING_OUTPUTS := cont.hBound

/-- Every TxContextContinuing carries outputs.length ≤ MAX as TYPE INVARIANT. -/
theorem continuing_outputs_length_is_invariant (cont : TxContextContinuing) :
    cont.outputs.length ≤ TXCONTEXT_MAX_CONTINUING_OUTPUTS := cont.hOutputsBound

/-- MAX = 2 (canonical constant from §14). -/
theorem max_continuing_is_two : TXCONTEXT_MAX_CONTINUING_OUTPUTS = 2 := rfl

/-- ALL continuings in a built bundle have count ≤ 2 (fold-level). -/
theorem buildTxContext_all_continuings_bounded
    (ids : List Nat) (hLen : ids.length > 0)
    (tin tout ht : Nat) (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContext ids tin tout ht cd = some bundle)
    (pair : Nat × TxContextContinuing)
    (hMem : pair ∈ bundle.continuingByExt) :
    pair.2.count ≤ 2 := by
  have hCd := buildTxContext_continuing_data ids hLen tin tout ht cd bundle hEq
  rw [hCd] at hMem; exact pair.2.hBound

/-- ALL continuings in a built bundle carry at most 2 actual outputs. -/
theorem buildTxContext_all_continuings_outputs_bounded
    (ids : List Nat) (hLen : ids.length > 0)
    (tin tout ht : Nat) (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContext ids tin tout ht cd = some bundle)
    (pair : Nat × TxContextContinuing)
    (hMem : pair ∈ bundle.continuingByExt) :
    pair.2.outputs.length ≤ 2 := by
  have hCd := buildTxContext_continuing_data ids hLen tin tout ht cd bundle hEq
  rw [hCd] at hMem
  exact pair.2.hOutputsBound

/-! ## Cross-property: value conservation (fee ≥ 0) -/

/-- If inputs ≥ outputs, bundle preserves totalIn ≥ totalOut. -/
theorem buildTxContextFromValues_value_conservation
    (ids : List Nat) (hLen : ids.length > 0)
    (inVals outVals : List Nat) (ht : Nat)
    (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildTxContextFromValues ids inVals outVals ht cd = some bundle)
    (hFee : sumInputValues inVals ≥ sumOutputValues outVals) :
    bundle.base.totalIn ≥ bundle.base.totalOut := by
  have hIn := buildTxContextFromValues_totalIn_real ids hLen inVals outVals ht cd bundle hEq
  have hOut := buildTxContextFromValues_totalOut_real ids hLen inVals outVals ht cd bundle hEq
  omega

/-! ## Live TxContext construction (§14 step 3c — R13)

Models the LIVE BuildTxContext path from Go connect_block_parallel.go.
Written as explicit match (no do) for formal proof access.
rfl-equivalent to buildTxContext / buildTxContextFromValues. -/

/-- Live TxContext construction: explicit bind with computed sums.
    Mirrors Go BuildTxContext — takes actual value lists, computes
    totalIn/totalOut via fold, returns bundle or none. -/
def buildTxContextLive
    (activeExtIds : List Nat)
    (inputValues outputValues : List Nat)
    (height : Nat)
    (continuingData : List (Nat × TxContextContinuing))
    : Option TxContextBundle :=
  if activeExtIds.length = 0 then none
  else
    let totalIn := inputValues.foldl (· + ·) 0
    let totalOut := outputValues.foldl (· + ·) 0
    some {
      base := { totalIn := totalIn, totalOut := totalOut, height := height }
      continuingByExt := continuingData
      continuingExtIds := sortExtIds activeExtIds
    }

/-- rfl equivalence: buildTxContextLive = buildTxContextFromValues. -/
theorem buildTxContextLive_eq_fromValues
    (ids : List Nat) (inVals outVals : List Nat) (h : Nat)
    (cd : List (Nat × TxContextContinuing)) :
    buildTxContextLive ids inVals outVals h cd =
    buildTxContextFromValues ids inVals outVals h cd := by
  simp [buildTxContextLive, buildTxContextFromValues, buildTxContext, sumInputValues, sumOutputValues]

/-- rfl equivalence: buildTxContextLive = buildTxContext with computed sums. -/
theorem buildTxContextLive_eq_buildTxContext
    (ids : List Nat) (inVals outVals : List Nat) (h : Nat)
    (cd : List (Nat × TxContextContinuing)) :
    buildTxContextLive ids inVals outVals h cd =
    buildTxContext ids (inVals.foldl (· + ·) 0) (outVals.foldl (· + ·) 0) h cd := by
  simp [buildTxContextLive, buildTxContext]

open UtxoApplyGenesisV1 in
/-- BRIDGE: live no-vault conservation path matches the model predicate. -/
theorem vault_bridge_no_vault (totalIn totalOut vis : Nat) :
    TxContext.checkValueConservation totalIn totalOut vis false = true ↔
    validateValueConservation totalOut totalIn 0 vis = .ok () := by
  simp only [TxContext.checkValueConservation, validateValueConservation]
  constructor
  · intro h
    by_cases h1 : totalOut > totalIn
    · simp [h1] at h
    · simp [h1] at h ⊢
  · intro h
    by_cases h1 : totalOut > totalIn
    · simp [h1] at h
    · simp [h1] at h ⊢

open UtxoApplyGenesisV1 in
/-- BRIDGE: live single-vault conservation path matches the model predicate. -/
theorem vault_bridge_with_vault (totalIn totalOut vis : Nat) :
    TxContext.checkValueConservation totalIn totalOut vis true = true ↔
    validateValueConservation totalOut totalIn 1 vis = .ok () := by
  simp only [TxContext.checkValueConservation, validateValueConservation]
  constructor
  · intro h
    by_cases h1 : totalOut > totalIn
    · simp [h1] at h
    · simp [h1] at h ⊢
      by_cases h2 : totalOut < vis <;> simp [h2] at h ⊢
  · intro h
    by_cases h1 : totalOut > totalIn
    · simp [h1] at h
    · simp [h1] at h ⊢
      by_cases h2 : totalOut < vis <;> simp [h2] at h ⊢

end RubinFormal
