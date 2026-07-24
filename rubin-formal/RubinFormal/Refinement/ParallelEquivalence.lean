/-
  ParallelEquivalence.lean — Formal refinement theorems for parallel validation.

  Proves the helper-level accept/reject contract for the parallel signature
  verification pipeline. This is the Q-PV-19 formal package.

  Architecture modeled:
  - Sequential: ConnectBlockBasicInMemoryAtHeight (canonical truth path)
  - Parallel:   ConnectBlockParallelSigVerify (IBD optimization)

  The parallel path:
  1. Runs all pre-checks sequentially (UTXO lookup, covenant parse, witness
     cursor assignment, value conservation) — identical to sequential.
  2. Collects signature verification tasks into a SigCheckQueue.
  3. Executes signature verifications in parallel via goroutine pool.
  4. Reduces results: any signature failure → block rejected.

  Key insight: since pre-checks are sequential and identical, the live bridge
  surface is the signature queue reducer contract:
  - accept iff every queued signature verifies;
  - reject iff any queued signature fails.

  This file does NOT claim exact surfaced error-index equivalence for the live
  queue. The Go SigCheckQueue may skip some later work after the first observed
  failure, so the surfaced error is deterministic by submission order but not a
  universal "lowest failing index" contract.
-/
import RubinFormal.CriticalInvariants

namespace RubinFormal.Refinement.ParallelEquivalence

open RubinFormal

/-- A signature check task: pure inputs for verification. -/
structure SigTask where
  suiteId : Nat
  pubkey : Bytes
  signature : Bytes
  digest : Bytes

-- ============================================================================
-- Section 1: Reducer — All-Pass / Any-Fail Equivalence
-- ============================================================================

/-- Sequential reduction: check tasks one by one, stop on first failure. -/
def reduceSeq (verify : SigTask → Bool) : List SigTask → Bool
  | [] => true
  | t :: rest => if verify t then reduceSeq verify rest else false

/-- Parallel reduction: check all tasks, combine results. -/
def reducePar (verify : SigTask → Bool) (tasks : List SigTask) : Bool :=
  tasks.all (fun t => verify t)

/-- Core equivalence: sequential and parallel reducers agree on accept/reject.
    If all sigs are valid, both accept; if any sig is invalid, both reject. -/
theorem reducer_equivalence (verify : SigTask → Bool) (tasks : List SigTask) :
    reduceSeq verify tasks = reducePar verify tasks := by
  induction tasks with
  | nil => rfl
  | cons t rest ih =>
    unfold reduceSeq reducePar
    simp only [List.all_cons]
    split
    · -- verify t = true
      rename_i hv
      simp only [hv, Bool.true_and]
      unfold reducePar at ih
      exact ih
    · -- verify t = false
      rename_i hv
      simp [hv]

-- ============================================================================
-- Section 2: Live Queue Contract Bridge
-- ============================================================================

/-- Transcription of the live Go `SigCheckQueue.Flush` accept/reject contract.
    The live queue may stop doing expensive crypto work after the first observed
    failure, but its externally visible success condition is simple: flush
    returns success iff every queued signature verifies. -/
def flushAccepts (verify : SigTask → Bool) (tasks : List SigTask) : Bool :=
  !(tasks.any (fun t => !(verify t)))

/-- Bridge theorem: the formal `reducePar` reducer and the live queue flush
    contract accept exactly the same batches. -/
theorem reducePar_eq_flushAccepts (verify : SigTask → Bool) (tasks : List SigTask) :
    reducePar verify tasks = flushAccepts verify tasks := by
  induction tasks with
  | nil => rfl
  | cons t rest ih =>
      unfold reducePar flushAccepts
      simp only [List.all_cons, List.any_cons]
      cases hvt : verify t with
      | false =>
          simp [hvt]
      | true =>
          simp [hvt]
          exact ih

/-- Block validation result. -/
inductive BlockResult
  | Accept (digest : Nat)
  | Reject (err : ErrorCode) (txIdx : Nat)
deriving DecidableEq

/-- Sequential block validation model. -/
def validateSeq (precheck : List α → Option (List SigTask × Nat))
    (verify : SigTask → Bool) (txs : List α) : BlockResult :=
  match precheck txs with
  | none => BlockResult.Reject ErrorCode.TxErrParse 0
  | some (sigTasks, digest) =>
    if reduceSeq verify sigTasks then BlockResult.Accept digest
    else BlockResult.Reject ErrorCode.TxErrSigInvalid 0

/-- Parallel block validation model. -/
def validatePar (precheck : List α → Option (List SigTask × Nat))
    (verify : SigTask → Bool) (txs : List α) : BlockResult :=
  match precheck txs with
  | none => BlockResult.Reject ErrorCode.TxErrParse 0
  | some (sigTasks, digest) =>
    if reducePar verify sigTasks then BlockResult.Accept digest
    else BlockResult.Reject ErrorCode.TxErrSigInvalid 0

/-- Live helper bridge for the parallel path: this models only the reducer
    contract that `SigCheckQueue.Flush` enforces in Go. It does not claim the
    full end-to-end block path or exact surfaced error-index parity. -/
def validateParLive (precheck : List α → Option (List SigTask × Nat))
    (verify : SigTask → Bool) (txs : List α) : BlockResult :=
  match precheck txs with
  | none => BlockResult.Reject ErrorCode.TxErrParse 0
  | some (sigTasks, digest) =>
    if flushAccepts verify sigTasks then BlockResult.Accept digest
    else BlockResult.Reject ErrorCode.TxErrSigInvalid 0

/-- The model-level parallel validator and the live queue reducer contract are
    extensionally equal on accept/reject. -/
theorem validatePar_eq_validateParLive
    (precheck : List α → Option (List SigTask × Nat))
    (verify : SigTask → Bool) (txs : List α) :
    validatePar precheck verify txs = validateParLive precheck verify txs := by
  simp [validatePar, validateParLive, reducePar_eq_flushAccepts]

/-- Accept/Reject equivalence: sequential and parallel validation produce
    the same verdict for any block. -/
theorem accept_reject_equivalence (precheck : List α → Option (List SigTask × Nat))
    (verify : SigTask → Bool) (txs : List α) :
    validateSeq precheck verify txs = validatePar precheck verify txs := by
  simp only [validateSeq, validatePar]
  cases h : precheck txs with
  | none => rfl
  | some pair =>
    obtain ⟨sigTasks, digest⟩ := pair
    simp only
    rw [reducer_equivalence]

/-- Sequential validation agrees with the live parallel queue contract on
    accept/reject. This is the counted bridge theorem for the actual Go helper
    surface, not a claim about exact surfaced error-index parity. -/
theorem accept_reject_equivalence_live
    (precheck : List α → Option (List SigTask × Nat))
    (verify : SigTask → Bool) (txs : List α) :
    validateSeq precheck verify txs = validateParLive precheck verify txs := by
  rw [← validatePar_eq_validateParLive]
  exact accept_reject_equivalence precheck verify txs

-- ============================================================================
-- Section 2b: Auxiliary Tagged-Result Error Index Model
-- ============================================================================

/-- Sequential first-failure index over pure worker results. -/
def firstRejectIndexFrom (start : Nat) : List Bool → Option Nat
  | [] => none
  | ok :: rest => if ok then firstRejectIndexFrom (start + 1) rest else some start

/-- Sequential first-failure index from zero. -/
def firstRejectIndex (results : List Bool) : Option Nat :=
  firstRejectIndexFrom 0 results

/-- Tag worker results with their canonical input index. -/
def indexedVerifyResultsFrom (start : Nat) : List Bool → List (Nat × Bool)
  | [] => []
  | ok :: rest => (start, ok) :: indexedVerifyResultsFrom (start + 1) rest

/-- Canonical tagged worker results from zero. -/
def indexedVerifyResults (results : List Bool) : List (Nat × Bool) :=
  indexedVerifyResultsFrom 0 results

/-- Parallel reducer returns the lowest failing canonical index, if any. -/
def lowestRejectIdx? : List (Nat × Bool) → Option Nat
  | [] => none
  | (idx, ok) :: rest =>
      let tail := lowestRejectIdx? rest
      if ok then tail
      else
        match tail with
        | none => some idx
        | some j => some (Nat.min idx j)

private theorem firstRejectIndexFrom_lower_bound (start idx : Nat) (results : List Bool)
    (h : firstRejectIndexFrom start results = some idx) :
    start ≤ idx := by
  induction results generalizing start idx with
  | nil => simp [firstRejectIndexFrom] at h
  | cons ok rest ih =>
      cases ok with
      | false =>
          simp [firstRejectIndexFrom] at h
          cases h
          exact Nat.le_refl _
      | true =>
          simp [firstRejectIndexFrom] at h
          exact Nat.le_trans (Nat.le_succ start) (ih (start + 1) idx h)

private theorem lowestRejectIdx_indexed_from (start : Nat) (results : List Bool) :
    lowestRejectIdx? (indexedVerifyResultsFrom start results) =
    firstRejectIndexFrom start results := by
  induction results generalizing start with
  | nil => rfl
  | cons ok rest ih =>
      cases ok with
      | false =>
          simp [indexedVerifyResultsFrom, lowestRejectIdx?, firstRejectIndexFrom]
          rw [ih (start + 1)]
          cases hrest : firstRejectIndexFrom (start + 1) rest with
          | none => simp [hrest]
          | some j =>
              have hge1 : start + 1 ≤ j := firstRejectIndexFrom_lower_bound (start + 1) j rest hrest
              have hge : start ≤ j := Nat.le_trans (Nat.le_succ start) hge1
              simp [hrest, Nat.min_eq_left hge]
      | true =>
          simp [indexedVerifyResultsFrom, lowestRejectIdx?, firstRejectIndexFrom, ih (start + 1)]

private theorem lowestRejectIdx_perm_invariant {xs ys : List (Nat × Bool)}
    (hperm : List.Perm xs ys) :
    lowestRejectIdx? xs = lowestRejectIdx? ys := by
  induction hperm with
  | nil => rfl
  | cons x _ ih => simp [lowestRejectIdx?, ih]
  | swap x y zs =>
      cases x with
      | mk i oki =>
          cases y with
          | mk j okj =>
              cases oki <;> cases okj <;> simp only [lowestRejectIdx?]
              all_goals (try rfl)
              all_goals (
                cases lowestRejectIdx? zs with
                | none => simp [Nat.min_def]; split <;> split <;> omega
                | some k => simp [Nat.min_def]; repeat (first | split | omega))
  | trans _ _ ih1 ih2 => exact ih1.trans ih2

/-- Auxiliary tagged-result theorem: any permutation of canonically indexed
    worker outputs preserves the lowest rejecting input index. This is useful
    for helper reasoning, but it is not counted as a bridge to the live queue,
    which only promises accept/reject plus deterministic submission-order
    surfacing under early abort. -/
theorem parallel_error_index_priority (results : List Bool)
    (parallel : List (Nat × Bool))
    (hperm : List.Perm parallel (indexedVerifyResults results)) :
    lowestRejectIdx? parallel = firstRejectIndex results := by
  calc
    lowestRejectIdx? parallel
        = lowestRejectIdx? (indexedVerifyResults results) := lowestRejectIdx_perm_invariant hperm
    _ = firstRejectIndexFrom 0 results := lowestRejectIdx_indexed_from 0 results
    _ = firstRejectIndex results := rfl

-- ============================================================================
-- Section 3: Context-Free Reducer Parity
-- ============================================================================

/-- A hypothetical context-dependent verifier would break parity. We prove
    that only context-free verifiers satisfy the parity requirement:
    if verify produces the same result under all contexts for all tasks,
    then reducePar is also context-invariant. -/
theorem context_free_reducer_parity
    (verifyA verifyB : SigTask → Bool)
    (tasks : List SigTask)
    (hAgree : ∀ t, t ∈ tasks → verifyA t = verifyB t) :
    reducePar verifyA tasks = reducePar verifyB tasks := by
  induction tasks with
  | nil => rfl
  | cons t rest ih =>
    unfold reducePar
    simp only [List.all_cons]
    have hHead := hAgree t (List.mem_cons_self t rest)
    have hRest : ∀ x, x ∈ rest → verifyA x = verifyB x :=
      fun x hx => hAgree x (List.mem_cons_of_mem t hx)
    rw [hHead]
    unfold reducePar at ih
    rw [ih hRest]

-- ============================================================================
-- Section 6: Graph Soundness (Dependency Ordering)
-- ============================================================================

-- In the PV architecture, pre-checks are sequential and handle all UTXO
-- resolution before sig verification begins. The sig verification phase
-- therefore has no dependencies between tasks — each task is independent.

/-- Sig task membership is preserved under permutation: if a task is in the
    original list, it is also in any permutation. Combined with verify being
    a pure function, this means every task gets checked regardless of order. -/
theorem sig_tasks_membership_preserved (tasks perm : List SigTask)
    (hPerm : perm.Perm tasks) (t : SigTask) :
    t ∈ tasks ↔ t ∈ perm := hPerm.symm.mem_iff

/-- The parallel reducer is permutation-invariant: reordering the sig task
    list does not change the aggregate accept/reject verdict. This is the
    key inter-task independence property — no task depends on another's
    position or execution order. -/
theorem reducer_permutation_invariant (verify : SigTask → Bool)
    (tasks perm : List SigTask) (hPerm : perm.Perm tasks) :
    reducePar verify tasks = reducePar verify perm := by
  unfold reducePar
  have : ∀ (f : SigTask → Bool), tasks.all f = perm.all f :=
    fun f => by
      induction hPerm with
      | nil => rfl
      | cons _ _ ih => simp [List.all_cons, ih]
      | swap _ _ _ => simp [List.all_cons, Bool.and_left_comm]
      | trans _ _ ih1 ih2 => exact ih2.trans ih1
  exact this _

/-- Precompute independence: after precompute, the aggregate verdict is
    invariant under any permutation of the sig task list. This encodes
    that UTXO resolution (precompute) eliminates all inter-task ordering
    dependencies — the remaining sig checks are truly independent. -/
theorem precompute_enables_reorder
    (precheck : List α → Option (List SigTask × Nat))
    (txs : List α)
    (verify : SigTask → Bool)
    (perm : List SigTask) :
    match precheck txs with
    | none => True
    | some (sigTasks, _) =>
      sigTasks.Perm perm → reducePar verify sigTasks = reducePar verify perm := by
  cases precheck txs with
  | none => trivial
  | some pair =>
    intro hPerm
    exact reducer_permutation_invariant verify pair.1 perm hPerm.symm

/-- The reducer verdict is invariant to task list reversal — a concrete
    instance of permutation invariance that directly models goroutine
    scheduling non-determinism. -/
theorem reducer_reverse_invariant (verify : SigTask → Bool) (tasks : List SigTask) :
    reducePar verify tasks = reducePar verify tasks.reverse := by
  exact reducer_permutation_invariant verify tasks tasks.reverse tasks.reverse_perm

end RubinFormal.Refinement.ParallelEquivalence
