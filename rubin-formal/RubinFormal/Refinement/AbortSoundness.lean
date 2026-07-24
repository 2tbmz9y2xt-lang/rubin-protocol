/-
  RubinFormal/Refinement/AbortSoundness.lean —
    Q-FORMAL-PARALLEL-VALIDATION-ABORT-SEMANTICS-01

  Proves abort/early-termination soundness for the parallel signature
  verification pipeline.

  Core property: if parallel validation is aborted after observing a
  signature failure (in any order, at any point), the abort decision is
  sound — the full evaluation would also have rejected the block.

  Architecture context:
  - Sequential path (reduceSeq): early-exits on first failure.
  - Parallel path (reducePar): evaluates all, then reduces.
  - Real runtime: goroutines process tasks in arbitrary order;
    on first observed failure, remaining work is cancelled.

  This module proves that the cancellation is safe: observing any single
  failure, or any failing prefix/subset, is sufficient to determine the
  final reject verdict.

  Builds on: ParallelEquivalence.lean (reducer_equivalence, reducePar, reduceSeq).
  Scope: formal model level. Runtime bridge (Go goroutine cancellation) is
  outside the Lean formal model boundary.
  Addresses #286.
-/

import RubinFormal.Refinement.ParallelEquivalence

namespace RubinFormal.Refinement.AbortSoundness

open RubinFormal.Refinement.ParallelEquivalence

-- ============================================================================
-- Section 1: Single Failure → Batch Rejection
-- ============================================================================

/-- If any single task in the batch fails verification, reducePar rejects
    the entire batch. This is the fundamental justification for abort-on-
    first-failure: observing one failure is sufficient. -/
theorem any_failure_rejects (verify : SigTask → Bool)
    (tasks : List SigTask) (t : SigTask)
    (hMem : t ∈ tasks) (hFail : verify t = false) :
    reducePar verify tasks = false := by
  induction tasks with
  | nil => exact absurd hMem (List.not_mem_nil t)
  | cons x rest ih =>
    unfold reducePar
    simp only [List.all_cons]
    rcases List.mem_cons.mp hMem with rfl | hRest
    · simp [hFail]
    · have ihRes := ih hRest
      unfold reducePar at ihRes
      cases verify x <;> simp [ihRes]

/-- Converse: if reducePar rejects, at least one task failed.
    Ensures abort decisions are not spurious — a rejection always has
    a concrete failing task as witness. -/
theorem rejects_has_witness (verify : SigTask → Bool)
    (tasks : List SigTask)
    (hFail : reducePar verify tasks = false) :
    ∃ t ∈ tasks, verify t = false := by
  induction tasks with
  | nil => unfold reducePar at hFail; simp at hFail
  | cons x rest ih =>
    unfold reducePar at hFail
    simp only [List.all_cons] at hFail
    by_cases hx : verify x = false
    · exact ⟨x, List.mem_cons_self x rest, hx⟩
    · have hx_true : verify x = true := by
        cases h : verify x
        · exact absurd h hx
        · rfl
      simp [hx_true] at hFail
      have ⟨t, hmem, hf⟩ := ih (by unfold reducePar; exact hFail)
      exact ⟨t, List.mem_cons_of_mem x hmem, hf⟩

-- ============================================================================
-- Section 2: Prefix Failure Propagation
-- ============================================================================

/-- Helper: if the full list passes, any prefix also passes.
    Contrapositive gives prefix failure → full failure. -/
private theorem all_prefix_of_all (f : SigTask → Bool)
    (xs : List SigTask) (k : Nat)
    (hall : xs.all f = true) :
    (xs.take k).all f = true := by
  induction xs generalizing k with
  | nil => simp
  | cons x rest ih =>
    cases k with
    | zero => simp
    | succ k' =>
      have htake : (x :: rest).take (k' + 1) = x :: rest.take k' := rfl
      rw [htake, List.all_cons]
      rw [List.all_cons] at hall
      have hx : f x = true := by
        cases hfx : f x
        · simp [hfx] at hall
        · rfl
      have hrest : rest.all f = true := by
        rw [hx, Bool.true_and] at hall; exact hall
      simp [hx, ih k' hrest]

/-- Prefix failure: if reducePar fails on a prefix (first k tasks),
    it fails on the full task list. This justifies aborting after
    observing partial failure during parallel evaluation.

    Runtime scenario: goroutine pool has processed k of n tasks;
    one of the first k failed. This theorem proves aborting the
    remaining n−k tasks is sound. -/
theorem prefix_failure_propagates (verify : SigTask → Bool)
    (tasks : List SigTask) (k : Nat)
    (hFail : reducePar verify (tasks.take k) = false) :
    reducePar verify tasks = false := by
  unfold reducePar at *
  cases hall : tasks.all (fun t => verify t) with
  | false => rfl
  | true =>
    have := all_prefix_of_all (fun t => verify t) tasks k hall
    simp [this] at hFail

-- ============================================================================
-- Section 3: Append / Concatenation Failure
-- ============================================================================

/-- Append failure: if the first batch already fails, adding more tasks
    doesn't change the verdict. Models: abort mid-batch is sound even
    if additional task batches remain in the queue. -/
theorem append_preserves_failure (verify : SigTask → Bool)
    (batch1 batch2 : List SigTask)
    (hFail : reducePar verify batch1 = false) :
    reducePar verify (batch1 ++ batch2) = false := by
  have ⟨t, hmem, hf⟩ := rejects_has_witness verify batch1 hFail
  exact any_failure_rejects verify (batch1 ++ batch2) t
    (List.mem_append_left batch2 hmem) hf

/-- Symmetric: failure in the second batch also propagates. -/
theorem append_preserves_failure_right (verify : SigTask → Bool)
    (batch1 batch2 : List SigTask)
    (hFail : reducePar verify batch2 = false) :
    reducePar verify (batch1 ++ batch2) = false := by
  have ⟨t, hmem, hf⟩ := rejects_has_witness verify batch2 hFail
  exact any_failure_rejects verify (batch1 ++ batch2) t
    (List.mem_append_right batch1 hmem) hf

-- ============================================================================
-- Section 4: Abort Soundness (reduceSeq ↔ reducePar bridge)
-- ============================================================================

/-- Abort soundness: reduceSeq's early-exit returning false implies
    reducePar's full evaluation also returns false.

    This is the explicit abort guarantee: the sequential path short-
    circuiting on first failure produces the same verdict as if all
    tasks had been evaluated. Direct corollary of reducer_equivalence,
    but stated explicitly for the abort semantics contract. -/
theorem abort_soundness (verify : SigTask → Bool) (tasks : List SigTask) :
    reduceSeq verify tasks = false →
    reducePar verify tasks = false := by
  intro h
  rwa [reducer_equivalence] at h

/-- Abort completeness: if reducePar rejects, reduceSeq also rejects
    (and does so after encountering the first failing task).
    Guarantees that the sequential early-exit path doesn't miss failures
    that the parallel path would catch. -/
theorem abort_completeness (verify : SigTask → Bool) (tasks : List SigTask) :
    reducePar verify tasks = false →
    reduceSeq verify tasks = false := by
  intro h
  rwa [← reducer_equivalence] at h

-- ============================================================================
-- Section 5: Block-Level Abort
-- ============================================================================

/-- Block abort soundness: if ANY signature in a block fails verification,
    the sequential block validator rejects the block. This connects the
    task-level abort semantics to the block-level validation model.

    Runtime scenario: parallel goroutine observes one sig failure →
    signals abort → block rejected. This theorem proves the abort
    produces the same BlockResult as full sequential evaluation. -/
theorem block_abort_on_sig_failure
    (precheck : List α → Option (List SigTask × Nat))
    (verify : SigTask → Bool) (txs : List α)
    (sigTasks : List SigTask) (digest : Nat)
    (hPre : precheck txs = some (sigTasks, digest))
    (t : SigTask) (hMem : t ∈ sigTasks) (hFail : verify t = false) :
    validateSeq precheck verify txs =
    BlockResult.Reject ErrorCode.TxErrSigInvalid 0 := by
  unfold validateSeq
  rw [hPre]
  simp only
  have hReject := any_failure_rejects verify sigTasks t hMem hFail
  rw [← reducer_equivalence] at hReject
  simp [hReject]

/-- Parallel block abort: the parallel validator also rejects on any
    sig failure. Combined with block_abort_on_sig_failure and
    accept_reject_equivalence, this shows: abort in either path
    produces identical BlockResult. -/
theorem block_abort_par_on_sig_failure
    (precheck : List α → Option (List SigTask × Nat))
    (verify : SigTask → Bool) (txs : List α)
    (sigTasks : List SigTask) (digest : Nat)
    (hPre : precheck txs = some (sigTasks, digest))
    (t : SigTask) (hMem : t ∈ sigTasks) (hFail : verify t = false) :
    validatePar precheck verify txs =
    BlockResult.Reject ErrorCode.TxErrSigInvalid 0 := by
  have hSeq := block_abort_on_sig_failure precheck verify txs sigTasks
    digest hPre t hMem hFail
  rw [accept_reject_equivalence precheck verify txs] at hSeq
  exact hSeq

-- ============================================================================
-- Section 6: Permuted Partial Evaluation
-- ============================================================================

/-- Permuted partial abort: if goroutines evaluate an arbitrary subset
    of tasks (in any order) and observe a failure, the full batch rejects.

    This is the most general abort theorem: it covers the real-world
    scenario where:
    1. Tasks are distributed to goroutines in non-deterministic order
    2. A goroutine observes a failure
    3. Remaining goroutines are cancelled
    4. The block is rejected

    The theorem proves step 4 is correct regardless of which subset
    was evaluated and in what order. -/
theorem permuted_partial_abort (verify : SigTask → Bool)
    (tasks evaluated : List SigTask)
    (hSub : ∀ t ∈ evaluated, t ∈ tasks)
    (t : SigTask) (hIn : t ∈ evaluated) (hFail : verify t = false) :
    reducePar verify tasks = false :=
  any_failure_rejects verify tasks t (hSub t hIn) hFail

end RubinFormal.Refinement.AbortSoundness
