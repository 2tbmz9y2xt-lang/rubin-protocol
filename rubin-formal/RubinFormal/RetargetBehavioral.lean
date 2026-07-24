import RubinFormal.PowV1
import RubinFormal.Conformance.CVPowReplay

/-!
# Difficulty Retarget Behavioral Proofs (§15)

Behavioral proofs on the retarget formula expressions from `PowV1.lean`.
These theorems operate on the pure arithmetic core (lines 143-146 of retargetV1),
not on the monadic `retargetV1` function directly. Live-function coverage is
provided by CV-POW conformance replay (`retarget_cv_replay_pass`).
Covers the three-way clamp path (lo/hi/candidate), constant pins,
timestamp clamping, candidate monotonicity, and 4x adjustment boundary.

Evidence level: machine_checked_contract (model + CV replay) for §15 retarget.
Combines:

1. Constant pins: windowSize, targetBlockInterval, tExpected, maxTimestampStepPerBlock, powLimit
2. Three-way clamp: lo ≤ result ≤ hi under valid preconditions
3. Identity/zero behavioral cases
4. 4x adjustment boundary: result ∈ [targetOld/4, min(targetOld*4, powLimit)]
5. Candidate monotonicity in tActual
6. Lo ≤ Hi proof under valid inputs (targetOldNat > 0, ≤ powLimit)
7. Conformance replay: cv_pow_vectors_pass (native_decide on real vectors)

Go equivalent: retargetV1 (consensus/pow.go)
Rust equivalent: retarget_v1 (rubin-consensus/src/pow.rs)
-/

namespace RubinFormal

open PowV1
/-! ## Helper: Nat division monotonicity

Lean 4.6.0 Init does not export `Nat.div_le_div_right`.
We prove it from `Nat.div_add_mod` + `Nat.mod_lt` by contradiction.
-/

/-- If a ≤ b and c > 0, then a / c ≤ b / c. -/
theorem nat_div_le_div_right {a b c : Nat} (hab : a ≤ b) (hc : 0 < c) : a / c ≤ b / c := by
  match Nat.lt_or_ge (b / c) (a / c) with
  | Or.inl h_lt =>
    have hcqa_le_a : c * (a / c) ≤ a := by
      have heq := Nat.div_add_mod a c
      have hle := Nat.le_add_right (c * (a / c)) (a % c)
      omega
    have hb_lt_cbqc : b < c * (b / c) + c := by
      have heq := Nat.div_add_mod b c
      have hmod := Nat.mod_lt b hc
      omega
    have hprod : c * (b / c) + c ≤ c * (a / c) := by
      have h1 := Nat.mul_le_mul_left c h_lt
      rw [Nat.mul_succ] at h1
      exact h1
    have : b < a := Nat.lt_of_lt_of_le (Nat.lt_of_lt_of_le hb_lt_cbqc hprod) hcqa_le_a
    exact absurd hab (Nat.not_le_of_lt this)
  | Or.inr h_ge => exact h_ge
/-! ## §15 Constants — canonical literal pins -/

/-- windowSize canonical literal pin (CANONICAL §15). -/
theorem retarget_window_size_value : windowSize = 10080 := rfl

/-- targetBlockInterval canonical literal pin (CANONICAL §15). -/
theorem retarget_block_interval_value : targetBlockInterval = 120 := rfl

/-- tExpected = windowSize * targetBlockInterval canonical pin (CANONICAL §15). -/
theorem retarget_tExpected_value : tExpected = 1209600 := by native_decide

/-- maxTimestampStepPerBlock canonical literal pin (CANONICAL §15). -/
theorem retarget_max_timestamp_step_value : maxTimestampStepPerBlock = 1200 := rfl

/-- powLimit = 2^256 - 1 canonical literal pin (CANONICAL §15). -/
theorem retarget_pow_limit_value : powLimit = 2^256 - 1 := rfl

/-- tExpected = windowSize * targetBlockInterval (structural). -/
theorem retarget_tExpected_decomposition :
    tExpected = targetBlockInterval * windowSize := rfl

/-! ## Identity and zero cases -/

/-- When tActual = tExpected, retarget candidate equals targetOldNat (identity). -/
theorem retarget_identity (targetOldNat : Nat) :
    (targetOldNat * tExpected) / tExpected = targetOldNat :=
  Nat.mul_div_cancel targetOldNat (by native_decide : 0 < tExpected)

/-- Retarget with zero actual time produces zero candidate. -/
theorem retarget_zero_tActual (targetOldNat : Nat) :
    (targetOldNat * 0) / tExpected = 0 := by simp
/-! ## Lo/Hi bounds -/

/-- Lo bound is always ≥ 1 (prevents zero-target). -/
theorem retarget_lo_positive (targetOldNat : Nat) :
    Nat.max 1 (targetOldNat / 4) ≥ 1 :=
  Nat.le_max_left 1 _

/-- Hi bound never exceeds powLimit. -/
theorem retarget_hi_bounded (targetOldNat : Nat) :
    Nat.min (targetOldNat * 4) powLimit ≤ powLimit :=
  Nat.min_le_right _ _

/-- Lo ≤ Hi under valid preconditions (targetOldNat > 0, ≤ powLimit).
    This resolves the limitation from the original RetargetBehavioral where
    retarget_clamped_in_range used max(lo,hi) instead of hi directly. -/
theorem retarget_lo_le_hi (targetOldNat : Nat)
    (hPos : targetOldNat > 0)
    (hBound : targetOldNat ≤ powLimit) :
    Nat.max 1 (targetOldNat / 4) ≤ Nat.min (targetOldNat * 4) powLimit := by
  apply Nat.max_le.mpr
  constructor
  · -- 1 ≤ min(targetOldNat * 4, powLimit)
    apply Nat.le_min.mpr
    constructor
    · omega
    · exact Nat.le_trans (by omega) hBound
  · -- targetOldNat / 4 ≤ min(targetOldNat * 4, powLimit)
    apply Nat.le_min.mpr
    constructor
    · exact Nat.le_trans (Nat.div_le_self _ _) (Nat.le_mul_of_pos_right targetOldNat (by omega))
    · exact Nat.le_trans (Nat.div_le_self _ _) hBound
/-! ## Clamped result range — strengthened version

With lo ≤ hi established, the clamped result is in [lo, hi] (not [lo, max(lo,hi)]).
-/

/-- Clamped result is always between lo and max(lo,hi). -/
theorem retarget_clamped_in_range (candidate lo hi : Nat) :
    lo ≤ Nat.max lo (Nat.min candidate hi) ∧
    Nat.max lo (Nat.min candidate hi) ≤ Nat.max lo hi := by
  constructor
  · exact Nat.le_max_left lo _
  · exact Nat.max_le.mpr ⟨Nat.le_max_left _ _, Nat.le_trans (Nat.min_le_right _ _) (Nat.le_max_right _ _)⟩

/-- Strengthened: under lo ≤ hi, clamped result is in [lo, hi]. -/
theorem retarget_clamped_in_range_strong (candidate lo hi : Nat) (hLoHi : lo ≤ hi) :
    lo ≤ Nat.max lo (Nat.min candidate hi) ∧
    Nat.max lo (Nat.min candidate hi) ≤ hi := by
  constructor
  · exact Nat.le_max_left lo _
  · apply Nat.max_le.mpr
    exact ⟨hLoHi, Nat.min_le_right _ _⟩

/-- Full range theorem: under valid inputs, retarget result ∈ [lo, hi]. -/
theorem retarget_result_in_valid_range (targetOldNat tActual : Nat)
    (hPos : targetOldNat > 0)
    (hBound : targetOldNat ≤ powLimit) :
    let candidate := (targetOldNat * tActual) / tExpected
    let lo := Nat.max 1 (targetOldNat / 4)
    let hi := Nat.min (targetOldNat * 4) powLimit
    let result := Nat.max lo (Nat.min candidate hi)
    lo ≤ result ∧ result ≤ hi := by
  dsimp
  exact retarget_clamped_in_range_strong _ _ _ (retarget_lo_le_hi targetOldNat hPos hBound)
/-! ## Candidate monotonicity

The candidate value `(targetOldNat * tActual) / tExpected` is monotone
in tActual — longer actual time → higher candidate → easier target.
-/

/-- Candidate is monotone in tActual. -/
theorem retarget_candidate_monotone (targetOldNat t1 t2 : Nat) (h : t1 ≤ t2) :
    (targetOldNat * t1) / tExpected ≤ (targetOldNat * t2) / tExpected :=
  nat_div_le_div_right (Nat.mul_le_mul_left targetOldNat h) (by native_decide : 0 < tExpected)

/-- Candidate is monotone in targetOldNat. -/
theorem retarget_candidate_monotone_target (t1 t2 tActual : Nat) (h : t1 ≤ t2) :
    (t1 * tActual) / tExpected ≤ (t2 * tActual) / tExpected :=
  nat_div_le_div_right (Nat.mul_le_mul_right tActual h) (by native_decide : 0 < tExpected)
/-! ## 4x adjustment boundary

The retarget never moves by more than 4x in either direction per window.
This is the fundamental stability property of the difficulty adjustment.
-/

/-- Lo bound: result ≥ targetOldNat / 4 (never drops by more than 4x). -/
theorem retarget_4x_lower (targetOldNat tActual : Nat) :
    let lo := Nat.max 1 (targetOldNat / 4)
    let hi := Nat.min (targetOldNat * 4) powLimit
    let candidate := (targetOldNat * tActual) / tExpected
    Nat.max lo (Nat.min candidate hi) ≥ targetOldNat / 4 := by
  dsimp
  exact Nat.le_trans (Nat.le_max_right 1 _) (Nat.le_max_left _ _)

/-- Hi bound: result ≤ targetOldNat * 4 (never increases by more than 4x). -/
theorem retarget_4x_upper (targetOldNat tActual : Nat)
    (hPos : 0 < targetOldNat) :
    let lo := Nat.max 1 (targetOldNat / 4)
    let hi := Nat.min (targetOldNat * 4) powLimit
    let candidate := (targetOldNat * tActual) / tExpected
    Nat.max lo (Nat.min candidate hi) ≤ targetOldNat * 4 := by
  dsimp
  apply Nat.max_le.mpr
  constructor
  · apply Nat.max_le.mpr
    constructor
    · omega
    · exact Nat.le_trans (Nat.div_le_self _ _) (Nat.le_mul_of_pos_right targetOldNat (by omega))
  · exact Nat.le_trans (Nat.min_le_right _ _) (Nat.min_le_left _ _)
/-! ## Timestamp clamping behavioral

The per-block timestamp step is clamped to [1, maxTimestampStepPerBlock].
This limits the effective tActual range for the retarget window.
-/

/-- Clamped timestamp step ≤ prev + maxTimestampStepPerBlock. -/
theorem timestamp_step_bounded (prevTs newTs : Nat) :
    Nat.min newTs (prevTs + maxTimestampStepPerBlock) ≤ prevTs + maxTimestampStepPerBlock :=
  Nat.min_le_right _ _

/-- Clamped timestamp step ≤ newTs (never exceeds actual). -/
theorem timestamp_step_le_actual (prevTs newTs : Nat) :
    Nat.min newTs (prevTs + maxTimestampStepPerBlock) ≤ newTs :=
  Nat.min_le_left _ _

/-- Max tActual over a full window is bounded by windowSize * maxTimestampStepPerBlock. -/
theorem max_tActual_bounded :
    windowSize * maxTimestampStepPerBlock = 12096000 := by native_decide

/-- Concrete check: max tActual / tExpected = 10 (max 10x difficulty increase per window). -/
theorem max_retarget_ratio :
    (windowSize * maxTimestampStepPerBlock) / tExpected = 10 := by native_decide

/-! ## Conformance replay bridge -/

/-- CV-POW conformance replay: all retarget vectors pass against the live
    `retargetV1` and `powCheck` implementations.  Proved by `native_decide`. -/
theorem retarget_cv_replay_pass :
    RubinFormal.Conformance.cvPowVectorsPass = true :=
  RubinFormal.Conformance.cv_pow_vectors_pass
/-! ## Behavioral closure summary

  The difficulty_update section (§15) model-level behavioral coverage:

  - **Constants**: all 6 normative constants pinned to literal values
  - **Identity**: tActual=tExpected → candidate = targetOldNat
  - **Zero**: tActual=0 → candidate = 0 (clamped to lo ≥ 1)
  - **Lo/Hi bounds**: lo ≥ 1, hi ≤ powLimit, lo ≤ hi (under valid preconditions)
  - **Clamped range**: result ∈ [lo, hi] (strengthened from [lo, max(lo,hi)])
  - **4x boundary**: result ∈ [targetOld/4, targetOld*4] (fundamental stability)
  - **Candidate monotonicity**: monotone in both tActual and targetOldNat
  - **Timestamp clamping**: per-block step bounded, max tActual bounded
  - **CV replay**: cv_pow_vectors_pass on real byte sequences
  - **Clamp bounded + positive**: from PowV1.lean (retargetV1_clamp_bounded/positive)

  Remaining non-claim: clampWindowTimestamps + tActualFromWindow for-loop chain
  for pattern=Some path requires Type C monad threading with u64Max overflow reasoning.
  Covered by CV-POW conformance replay (`retarget_cv_replay_pass`).
-/

/-! ## LIVE theorems on retargetV1 (monadic function)

These theorems reference `retargetV1` directly, establishing LIVE class coverage
for the difficulty_update section. They prove error validation paths and
output structure of the actual monadic live function.
-/

/-- LIVE: retargetV1 rejects unparseable targetOld (wrong byte length). -/
theorem retargetV1_parse_none (targetOld : Bytes) (ts1 ts2 : Nat) (p : Option WindowPattern)
    (h : PowV1.bytesToNatBE32? targetOld = none) :
    PowV1.retargetV1 targetOld ts1 ts2 p = .error "TX_ERR_PARSE" := by
  unfold PowV1.retargetV1
  simp only [h, bind, Except.bind]

/-- LIVE: retargetV1 rejects zero-value target. -/
theorem retargetV1_zero_target (targetOld : Bytes) (ts1 ts2 : Nat) (p : Option WindowPattern)
    (h : PowV1.bytesToNatBE32? targetOld = some 0) :
    PowV1.retargetV1 targetOld ts1 ts2 p = .error "TX_ERR_PARSE" := by
  unfold PowV1.retargetV1
  simp only [h, bind, Except.bind, pure, Except.pure]
  rfl

/-- LIVE: retargetV1 with valid inputs and pattern=none produces .ok output. -/
theorem retargetV1_ok_none_simple (targetOld : Bytes) (ts1 ts2 : Nat)
    (n : Nat)
    (hParse : PowV1.bytesToNatBE32? targetOld = some n)
    (hNZ : n ≠ 0) (hBound : n ≤ PowV1.powLimit)
    (hTs1 : ts1 ≤ PowV1.u64Max) (hTs2 : ts2 ≤ PowV1.u64Max) (hOrd : ts1 < ts2) :
    ∃ result, PowV1.retargetV1 targetOld ts1 ts2 none = .ok result := by
  unfold PowV1.retargetV1
  simp only [hParse, bind, Except.bind, pure, Except.pure]
  split
  · rename_i h; simp [BEq.beq] at h; exact absurd h hNZ
  · split
    · rename_i _ h; exact absurd (Nat.le_of_lt_succ (Nat.lt_succ_of_le hBound)) (Nat.not_le_of_gt h)
    · simp only [PowV1.u64Max] at hTs1 hTs2
      split
      · rename_i h
        exfalso
        simp only [Bool.or_eq_true, decide_eq_true_eq] at h
        omega
      · split
        · rename_i _ h; exfalso; omega
        · exact ⟨_, rfl⟩

/-! ## bytesToNatBE32? output bound (LIVE, closes Gap 3)

The for-loop `for i in [0:32] do acc := acc * 256 + b` is opaque to Lean tactics
due to `@[extern]` forIn. Strategy: define a recursive mirror, prove bound by
induction, then bridge to the original via `Std.Range.forIn.loop` unfolding.
-/

/-- Recursive byte accumulator: proof-friendly mirror of the for-loop in bytesToNatBE32?. -/
def bytesAccRec (bs : Bytes) : Nat → Nat → Nat → Nat
  | _, 0, acc => acc
  | start, k + 1, acc =>
      bytesAccRec bs (start + 1) k (acc * 256 + (bs.get! start).toNat)

set_option maxRecDepth 1024 in
set_option maxHeartbeats 800000 in
/-- BRIDGE: bytesToNatBE32? equals the recursive accumulator when bs.size = 32. -/
theorem bytesToNatBE32_eq_rec (bs : Bytes) (hSz : bs.size = 32) :
    PowV1.bytesToNatBE32? bs = some (bytesAccRec bs 0 32 0) := by
  unfold PowV1.bytesToNatBE32?
  simp only [hSz, Id.run, forIn, Std.Range.forIn, Std.Range.forIn.loop]
  rfl

/-- Every UInt8 has toNat ≤ 255. -/
private theorem byte_le (b : UInt8) : b.toNat ≤ 255 := by
  have h : b.toNat < 256 := b.val.isLt; omega

/-- LIVE: Loop invariant — bytesAccRec with acc < 256^start produces result < 256^(start+k). -/
theorem bytesAccRec_bound (bs : Bytes) (start k : Nat) (acc : Nat)
    (hAcc : acc < 256 ^ start) :
    bytesAccRec bs start k acc < 256 ^ (start + k) := by
  induction k generalizing start acc with
  | zero => simp only [bytesAccRec, Nat.add_zero]; exact hAcc
  | succ n ih =>
    unfold bytesAccRec
    have hStep : acc * 256 + (bs.get! start).toNat < 256 ^ (start + 1) := by
      have h1 := Nat.mul_le_mul_right 256 (Nat.le_sub_one_of_lt hAcc)
      have h2 : (256 ^ start - 1) * 256 + 255 = 256 ^ (start + 1) - 1 := by
        rw [Nat.pow_succ]; omega
      have := byte_le (bs.get! start); omega
    rw [← show start + 1 + n = start + (n + 1) from by omega]
    exact ih (start + 1) _ hStep

/-- bytesToNatBE32? returns none when bs.size ≠ 32. -/
theorem bytesToNatBE32_none_of_size_ne (bs : Bytes) (h : bs.size ≠ 32) :
    PowV1.bytesToNatBE32? bs = none := by
  unfold PowV1.bytesToNatBE32?; simp [h]

/-- If bytesToNatBE32? returns some, then bs.size = 32. -/
theorem bytesToNatBE32_size (bs : Bytes) (n : Nat)
    (h : PowV1.bytesToNatBE32? bs = some n) : bs.size = 32 := by
  by_contra hne; rw [bytesToNatBE32_none_of_size_ne bs hne] at h; simp at h

/-- LIVE: bytesToNatBE32? output is strictly less than 256^32. -/
theorem bytesToNatBE32_lt (bs : Bytes) (n : Nat)
    (h : PowV1.bytesToNatBE32? bs = some n) : n < 256 ^ 32 := by
  have hSz := bytesToNatBE32_size bs n h
  rw [bytesToNatBE32_eq_rec bs hSz] at h
  injection h with h; rw [← h]
  exact bytesAccRec_bound bs 0 32 0 (by decide)

/-- LIVE: bytesToNatBE32? output is bounded by powLimit = 2^256 - 1.
    This is the key theorem closing Gap 3 — it proves that the `n > powLimit`
    guard in retargetV1 is dead code, removing a reviewer-flagged limitation. -/
theorem bytesToNatBE32_le_powLimit (bs : Bytes) (n : Nat)
    (h : PowV1.bytesToNatBE32? bs = some n) : n ≤ PowV1.powLimit := by
  have hLt := bytesToNatBE32_lt bs n h
  have : (256 : Nat) ^ 32 = 2 ^ 256 := by native_decide
  rw [this] at hLt; unfold PowV1.powLimit; omega

/-! ## retargetV1 over_limit is dead code (LIVE, closes Gap 2)

With `bytesToNatBE32_le_powLimit`, the `n > powLimit` guard in retargetV1
is provably unreachable: bytesToNatBE32? produces at most 2^256 - 1 = powLimit. -/

/-- LIVE: retargetV1's `n > powLimit` error path is unreachable —
    bytesToNatBE32? by construction produces n ≤ powLimit. -/
theorem retargetV1_overlimit_dead (targetOld : Bytes) (n : Nat)
    (hParse : PowV1.bytesToNatBE32? targetOld = some n) :
    ¬ (n > PowV1.powLimit) :=
  Nat.not_lt_of_le (bytesToNatBE32_le_powLimit targetOld n hParse)

/-! ## genWindowTimestamps succeeds under valid preconditions (LIVE, partial Gap 1)

The only failure paths in genWindowTimestamps are two early guards:
windowSize < 2 and windowSize ≠ canonical. After guards pass, the Id.run
for-loop block is pure computation. -/

/-- LIVE: genWindowTimestamps succeeds when p.windowSize = windowSize. -/
theorem genWindowTimestamps_ok (p : PowV1.WindowPattern)
    (hWS : p.windowSize = PowV1.windowSize) :
    ∃ ts, PowV1.genWindowTimestamps p = .ok ts := by
  show ∃ ts, PowV1.genWindowTimestamps p = Except.ok ts
  rw [show PowV1.genWindowTimestamps p =
      (do if p.windowSize < 2 then throw "TX_ERR_PARSE"
          if p.windowSize != PowV1.windowSize then throw "TX_ERR_PARSE"
          let out : Array Nat := Id.run do
            let mut ts : Array Nat := Array.mkEmpty p.windowSize
            let mut prev : Nat := p.start
            ts := ts.push prev
            for _ in [0:(p.windowSize - 1)] do
              let next := prev + p.step
              ts := ts.push next
              prev := next
            if p.lastJump != 0 then
              let secLast := ts.get! (p.windowSize - 2)
              ts := ts.set! (p.windowSize - 1) (secLast + p.lastJump)
            return ts
          pure out.toList : Except String (List Nat))
    from by unfold PowV1.genWindowTimestamps; rfl]
  have hNotLt : ¬ (p.windowSize < 2) := by rw [hWS]; unfold PowV1.windowSize; omega
  have hEq : ¬ (p.windowSize != PowV1.windowSize) := by simp [bne, BEq.beq, hWS]
  simp only [hNotLt, ↓reduceIte, hEq, bind, Except.bind, pure, Except.pure]
  exact ⟨_, rfl⟩

/-! ## clampWindowTimestamps: direct for-loop invariant (LIVE+BRIDGE)

The for-loop in clampWindowTimestamps iterates over `rest : List Nat` with two
mutable variables (prev, acc) and three early-return paths on u64Max overflow.
Strategy: extract the for-loop body as `cwsInnerGen`, prove non-emptiness
by induction using `List.forIn.loop` unfolding, then bridge to clampWindowTimestamps
via opaque unfold + definitional equality. -/

private theorem list_forIn_loop_cons' {α β : Type} (f : α → β → Id (ForInStep β))
    (a : α) (as : List α) (s : β) :
    List.forIn.loop f (a :: as) s =
    (match f a s with | .yield s' => List.forIn.loop f as s' | .done s' => s') := by
  simp [List.forIn.loop, List.brecOn]; cases f a s with | yield s' => rfl | done s' => rfl

private theorem clamp_le' (v lo hi : Nat) (h : lo ≤ hi) : PowV1.clamp v lo hi ≤ hi := by
  unfold PowV1.clamp; exact Nat.max_le.mpr ⟨h, Nat.min_le_right _ _⟩

private theorem arr_toList_ne_nil (a : Array Nat) (h : a.size > 0) : a.toList ≠ [] := by
  rw [Array.toList_eq]; intro he
  exact absurd (show a.size = 0 from by unfold Array.size; rw [he]; rfl) (by omega)

/-- Named extraction of the clampWindowTimestamps for-loop, parameterized for induction. -/
def cwsInnerGen (rest : List Nat) (prev : Nat) (acc : Array Nat) : Array Nat :=
  Id.run do
    let mut p := prev; let mut a := acc
    for t in rest do
      if t > PowV1.u64Max then return #[]
      let lo := p + 1; let hi := p + PowV1.maxTimestampStepPerBlock
      if lo > PowV1.u64Max || hi > PowV1.u64Max then return #[]
      let t' := PowV1.clamp t lo hi; a := a.push t'; p := t'
    return a

/-- LIVE: Direct for-loop invariant — under bounded timestamps, cwsInnerGen produces
    non-empty output. Proved by induction on rest using List.forIn.loop unfolding.
    Each step: by_cases on guards eliminates overflow → yield preserves size > 0. -/
theorem cwsInnerGen_nonempty (rest : List Nat) (prev : Nat) (acc : Array Nat)
    (hAcc : acc.size > 0) (hAll : ∀ t ∈ rest, t ≤ PowV1.u64Max)
    (hBound : prev + (rest.length + 1) * 1200 ≤ PowV1.u64Max) :
    (cwsInnerGen rest prev acc).size > 0 := by
  induction rest generalizing prev acc with
  | nil => simp [cwsInnerGen, Id.run, forIn, List.forIn, List.forIn.loop, List.brecOn]; exact hAcc
  | cons t ts ih =>
    unfold cwsInnerGen
    simp only [Id.run, forIn, List.forIn, list_forIn_loop_cons']
    have ht := hAll t (List.mem_cons_self _ _)
    have hPB : prev + 1200 ≤ PowV1.u64Max := by simp only [List.length_cons] at hBound; omega
    by_cases h1 : t > PowV1.u64Max
    · exfalso; omega
    · simp only [h1, ↓reduceIte]
      by_cases h2 : (decide (prev + 1 > PowV1.u64Max) ||
          decide (prev + PowV1.maxTimestampStepPerBlock > PowV1.u64Max)) = true
      · exfalso
        simp [Bool.or_eq_true, decide_eq_true_eq,
          show PowV1.maxTimestampStepPerBlock = 1200 from rfl] at h2; omega
      · simp only [h2, ↓reduceIte]
        have hC : PowV1.clamp t (prev + 1) (prev + PowV1.maxTimestampStepPerBlock) ≤ prev + 1200 := by
          rw [show PowV1.maxTimestampStepPerBlock = 1200 from rfl]; exact clamp_le' t _ _ (by omega)
        exact ih _ _ (by simp [Array.size_push]) (fun x hx => hAll x (List.mem_cons_of_mem _ hx))
          (by simp only [List.length_cons] at hBound
              exact Nat.le_trans (Nat.add_le_add_right hC _) (by omega))

/-- LIVE+BRIDGE: clampWindowTimestamps succeeds with non-empty output under bounded timestamps.
    Bridges cwsInnerGen (named for-loop) to clampWindowTimestamps (live function)
    via opaque unfold + definitional equality. -/
theorem clampWindowTimestamps_ok (t0 : Nat) (rest : List Nat)
    (hT0 : t0 ≤ PowV1.u64Max) (hAll : ∀ t ∈ rest, t ≤ PowV1.u64Max)
    (hBound : t0 + (rest.length + 1) * 1200 ≤ PowV1.u64Max) :
    ∃ ts, PowV1.clampWindowTimestamps (t0 :: rest) = .ok ts ∧ ts ≠ [] := by
  rw [show PowV1.clampWindowTimestamps (t0 :: rest) =
      (do if t0 > PowV1.u64Max then throw "TX_ERR_PARSE"
          let out : Array Nat := cwsInnerGen rest t0 (#[t0])
          if out.isEmpty then throw "TX_ERR_PARSE"
          pure out.toList : Except String (List Nat))
    from by unfold PowV1.clampWindowTimestamps cwsInnerGen; rfl]
  simp only [show ¬ (t0 > PowV1.u64Max) from by omega, ↓reduceIte,
             bind, Except.bind, pure, Except.pure]
  have hSz := cwsInnerGen_nonempty rest t0 #[t0] (by simp [Array.size_push]) hAll hBound
  simp only [show ¬ (cwsInnerGen rest t0 #[t0]).isEmpty from by simp [Array.isEmpty]; omega, ↓reduceIte]
  exact ⟨_, rfl, arr_toList_ne_nil _ hSz⟩

/-! ## tActualFromWindow: success under bounded timestamps (LIVE)

Composes clampWindowTimestamps_ok with pattern-match on the non-empty result. -/

/-- LIVE: tActualFromWindow succeeds when clampWindowTimestamps succeeds with non-empty output. -/
theorem tActualFromWindow_ok_of_clamp (ts : List Nat) (ts' : List Nat)
    (hClamp : PowV1.clampWindowTimestamps ts = .ok ts')
    (hNe : ts' ≠ []) :
    ∃ v, PowV1.tActualFromWindow ts = .ok v := by
  unfold PowV1.tActualFromWindow
  simp only [hClamp, bind, Except.bind]
  cases ts' with
  | nil => exact absurd rfl hNe
  | cons first rest =>
    simp only [pure, Except.pure]
    split
    · exact ⟨_, rfl⟩
    · exact ⟨_, rfl⟩

end RubinFormal
