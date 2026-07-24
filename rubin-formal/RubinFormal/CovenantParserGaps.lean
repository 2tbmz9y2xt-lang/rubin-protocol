/-
  CovenantParserGaps.lean — formal gap coverage for covenant parsers (#298)

  ALL theorems are LIVE (∀-quantified over live parser code).
  Zero MODEL / native_decide theorems.

  Coverage:
    Multisig parser:    size guard, keyCount bounds, threshold bounds, size-match,
                        keys sorted post-condition (through forIn)
    HTLC parser:        size guard, 3 post-conditions (claim≠refund, lockMode, lockValue)
    validateOutGenesis: unknown covenant type exhaustion
-/
import RubinFormal.Types
import RubinFormal.CovenantGenesisV1

set_option maxHeartbeats 4000000

namespace RubinFormal

open Wire CovenantGenesisV1

-- ═══════════════════════════════════════════════════════════════════
-- §1  Multisig parser — size guard  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ input shorter than 34 bytes → multisig parser rejects.
    Mirrors Go `if len(covData) < 34` / Rust `if cov_data.len() < 34`. -/
theorem multisig_size_guard (covData : Bytes) (h : covData.size < 34) :
    parseMultisigCovenantData covData = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  unfold parseMultisigCovenantData
  simp [h, Bind.bind, Except.bind, throw, MonadExcept.throw, Except.error]

-- ═══════════════════════════════════════════════════════════════════
-- §2  Multisig parser — keyCount bounds guard  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ input where size ≥ 34 but keyCount ∉ [1..12] → rejected.
    Mirrors Go/Rust `if keyCount < 1 || keyCount > 12`. -/
theorem multisig_keycount_bounds_guard (covData : Bytes)
    (h_size : ¬(covData.size < 34))
    (h_kc : (covData.get! 1).toNat < 1 ∨ (covData.get! 1).toNat > MAX_MULTISIG_KEYS) :
    parseMultisigCovenantData covData = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  unfold parseMultisigCovenantData MAX_MULTISIG_KEYS
  simp only [h_size, ite_false]
  dsimp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
             throwThe, MonadExcept.throw, MonadExceptOf.throw]
  split
  · simp [Bind.bind, Except.bind, throwThe, MonadExcept.throw]
  · rename_i h_in; exfalso; unfold MAX_MULTISIG_KEYS at h_kc
    rcases h_kc with h_lo | h_hi <;> simp_all

-- ═══════════════════════════════════════════════════════════════════
-- §3  Multisig parser — threshold bounds guard  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ input passing size+keyCount guards but threshold ∉ [1..keyCount] → rejected.
    Mirrors Go/Rust `if threshold < 1 || threshold > keyCount`. -/
theorem multisig_threshold_bounds_guard (covData : Bytes)
    (h_size : ¬(covData.size < 34))
    (h_kc : ¬((covData.get! 1).toNat < 1 ∨ (covData.get! 1).toNat > MAX_MULTISIG_KEYS))
    (h_th : (covData.get! 0).toNat < 1 ∨ (covData.get! 0).toNat > (covData.get! 1).toNat) :
    parseMultisigCovenantData covData = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  unfold parseMultisigCovenantData MAX_MULTISIG_KEYS
  simp only [h_size, ite_false]
  dsimp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
             throwThe, MonadExcept.throw, MonadExceptOf.throw]
  split
  · rename_i h_bad; exfalso; unfold MAX_MULTISIG_KEYS at h_kc; simp_all
  · split
    · simp [Bind.bind, Except.bind, throwThe, MonadExcept.throw]
    · rename_i h_th_in; exfalso
      rcases h_th with h_lo | h_hi <;> simp_all

-- ═══════════════════════════════════════════════════════════════════
-- §4  Multisig parser — size-match guard  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ input passing size/keyCount/threshold guards but
    covData.size ≠ 2 + 32 * keyCount → rejected.
    Mirrors Go/Rust `if len(covData) != 2 + 32*keyCount`. -/
theorem multisig_size_match_guard (covData : Bytes)
    (h_size : ¬(covData.size < 34))
    (h_kc : ¬((covData.get! 1).toNat < 1 ∨ (covData.get! 1).toNat > MAX_MULTISIG_KEYS))
    (_h_th : ¬((covData.get! 0).toNat < 1 ∨ (covData.get! 0).toNat > (covData.get! 1).toNat))
    (h_len : covData.size ≠ 2 + 32 * (covData.get! 1).toNat) :
    parseMultisigCovenantData covData = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  unfold parseMultisigCovenantData MAX_MULTISIG_KEYS
  simp only [h_size, ite_false]
  dsimp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
             throwThe, MonadExcept.throw, MonadExceptOf.throw]
  split
  · rename_i h_bad; exfalso; unfold MAX_MULTISIG_KEYS at h_kc; simp_all
  · split
    · -- threshold bad → parser already throws here
      simp [Bind.bind, Except.bind, throwThe, MonadExcept.throw]
    · -- threshold good → proceed to size-match check
      split
      · simp [Bind.bind, Except.bind, throwThe, MonadExcept.throw]
      · rename_i h_len_ok; exfalso
        simp_all [bne, beq_iff_eq]

-- ═══════════════════════════════════════════════════════════════════
-- §5  Multisig post-condition: keys are strictly sorted  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ successful multisig parse, strictlySortedUnique32 holds on output keys.
    Proof traverses the forIn loop opaquely and then splits on the
    post-loop `if !strictlySortedUnique32 keys` guard. -/
theorem multisig_ok_keys_sorted (covData : Bytes) (v : MultisigCovenant)
    (h : parseMultisigCovenantData covData = .ok v) :
    strictlySortedUnique32 v.keys = true := by
  unfold parseMultisigCovenantData MAX_MULTISIG_KEYS at h
  split at h
  · simp only [Bind.bind, Except.bind, throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
  · dsimp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
               throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · -- past all 4 pre-loop guards, forIn + strictlySortedUnique32 check remain
          split at h
          · simp at h  -- forIn error branch
          · -- forIn ok branch, h still has strictlySortedUnique32 check
            split at h
            · simp at h  -- strictlySortedUnique32 fails → .error contradicts .ok
            · -- strictlySortedUnique32 passes → .ok { ... keys := keys' } = .ok v
              cases h
              simp_all

-- ═══════════════════════════════════════════════════════════════════
-- §6  HTLC parser — size guard  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ input whose size ≠ MAX_HTLC_COVENANT_DATA (105) → rejected.
    Uses split to avoid whnf timeout on the large else branch. -/
theorem htlc_size_guard (covData : Bytes) (h : covData.size ≠ MAX_HTLC_COVENANT_DATA) :
    parseHtlcCovenantData covData = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  unfold parseHtlcCovenantData MAX_HTLC_COVENANT_DATA
  split
  · simp [Bind.bind, Except.bind, throwThe, MonadExcept.throw]
  · rename_i hne; exfalso; apply hne
    unfold MAX_HTLC_COVENANT_DATA at h
    simp [bne, beq_iff_eq, h]

-- ═══════════════════════════════════════════════════════════════════
-- §7  validateOutGenesis — unknown type exhaustion  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ covenantType outside the six known types → rejected.
    Proves the if-else chain in validateOutGenesis is exhaustive. -/
theorem validate_out_genesis_rejects_unknown (out : TxOut) (txKind bh : Nat)
    (h1 : out.covenantType ≠ COV_TYPE_P2PK)
    (h2 : out.covenantType ≠ COV_TYPE_ANCHOR)
    (h3 : out.covenantType ≠ COV_TYPE_VAULT)
    (h4 : out.covenantType ≠ COV_TYPE_MULTISIG)
    (h5 : out.covenantType ≠ COV_TYPE_HTLC)
    (h6 : out.covenantType ≠ COV_TYPE_DA_COMMIT) :
    validateOutGenesis out txKind bh = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  simp only [COV_TYPE_P2PK, COV_TYPE_ANCHOR, COV_TYPE_VAULT,
             COV_TYPE_MULTISIG, COV_TYPE_HTLC, COV_TYPE_DA_COMMIT] at h1 h2 h3 h4 h5 h6
  unfold validateOutGenesis COV_TYPE_P2PK COV_TYPE_ANCHOR COV_TYPE_VAULT
         COV_TYPE_MULTISIG COV_TYPE_HTLC COV_TYPE_DA_COMMIT
  simp [h1, h2, h3, h4, h5, h6, beq_iff_eq,
        Bind.bind, Except.bind, Pure.pure, Except.pure,
        throwThe, MonadExceptOf.throw, MonadExcept.throw, Except.error]

-- ═══════════════════════════════════════════════════════════════════
-- HTLC parser post-conditions — shared tactic skeleton
--
-- Approach: unfold the monadic `do` block, then use `split at h` to
-- step through each guard one at a time.  Between splits, `dsimp only`
-- collapses the join-point bind chains.  At the end, `cases h`
-- destructs the .ok injection, and we close using the relevant
-- split hypothesis.
-- ═══════════════════════════════════════════════════════════════════

-- ═══════════════════════════════════════════════════════════════════
-- §8  HTLC post-condition: claim ≠ refund  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ successful HTLC parse, claimKeyId ≠ refundKeyId (Bool-level).
    The parser guard `if claim == refund then throw "TX_ERR_PARSE"`
    ensures this invariant for all inputs. -/
theorem htlc_ok_claim_neq_refund (covData : Bytes) (v : HtlcCovenant)
    (h : parseHtlcCovenantData covData = .ok v) :
    (v.claimKeyId == v.refundKeyId) = false := by
  unfold parseHtlcCovenantData MAX_HTLC_COVENANT_DATA LOCK_MODE_HEIGHT LOCK_MODE_TIMESTAMP at h
  split at h
  · simp only [Bind.bind, Except.bind, throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
  · dsimp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
               throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · -- rename_i gives: h_lm=lockMode, h_lv=lockValue, h_cr=claim (context order)
          rename_i h_lm h_lv h_cr
          cases h
          -- h_cr : ¬((claim == refund) = true), goal: (claim == refund) = false
          revert h_cr; simp

-- ═══════════════════════════════════════════════════════════════════
-- §9  HTLC post-condition: lockMode valid  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ successful HTLC parse, lockMode ∈ {HEIGHT, TIMESTAMP}.
    The parser guard `if !(lockMode == 0 || lockMode == 1) then throw`
    ensures this for all inputs. -/
theorem htlc_ok_lock_mode_valid (covData : Bytes) (v : HtlcCovenant)
    (h : parseHtlcCovenantData covData = .ok v) :
    (v.lockMode == LOCK_MODE_HEIGHT || v.lockMode == LOCK_MODE_TIMESTAMP) = true := by
  unfold parseHtlcCovenantData MAX_HTLC_COVENANT_DATA LOCK_MODE_HEIGHT LOCK_MODE_TIMESTAMP at h
  split at h
  · simp only [Bind.bind, Except.bind, throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
  · dsimp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
               throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · rename_i h_lm h_lv h_cr
          cases h
          -- h_lm : ¬(!(lockMode == 0 || lockMode == 1) = true)
          -- goal: (lockMode == LOCK_MODE_HEIGHT || lockMode == LOCK_MODE_TIMESTAMP) = true
          unfold LOCK_MODE_HEIGHT LOCK_MODE_TIMESTAMP
          revert h_lm; simp

-- ═══════════════════════════════════════════════════════════════════
-- §10  HTLC post-condition: lockValue > 0  [LIVE]
-- ═══════════════════════════════════════════════════════════════════

/-- [LIVE] ∀ successful HTLC parse, lockValue ≠ 0.
    The parser guard `if lockValue == 0 then throw` ensures this. -/
theorem htlc_ok_lock_value_nonzero (covData : Bytes) (v : HtlcCovenant)
    (h : parseHtlcCovenantData covData = .ok v) :
    (v.lockValue == 0) = false := by
  unfold parseHtlcCovenantData MAX_HTLC_COVENANT_DATA LOCK_MODE_HEIGHT LOCK_MODE_TIMESTAMP at h
  split at h
  · simp only [Bind.bind, Except.bind, throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
  · dsimp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
               throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · rename_i h_lm h_lv h_cr
          cases h
          -- h_lv : ¬((lockValue == 0) = true), goal: (lockValue == 0) = false
          revert h_lv; simp

end RubinFormal
