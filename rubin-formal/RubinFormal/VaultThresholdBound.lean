/-
  VaultThresholdBound.lean — vault threshold ≤ keyCount post-condition (#294)

  LIVE theorem on parseVaultCovenantData: if parse succeeds,
  threshold ∈ [1..keyCount].
-/
import RubinFormal.Types
import RubinFormal.CovenantGenesisV1

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire CovenantGenesisV1

/-- [LIVE] ∀ successful vault parse, threshold ∈ [1..keyCount].
    The parser guard `if threshold < 1 || threshold > keyCount then throw`
    ensures this for all inputs.  Proof traverses all post-guard code
    (two forIn loops, sorted checks, size checks) via split-at-h. -/
theorem vault_ok_threshold_le_keycount (covData : Bytes) (v : VaultCovenant)
    (h : parseVaultCovenantData covData = .ok v) :
    v.threshold ≥ 1 ∧ v.threshold ≤ v.keyCount := by
  unfold parseVaultCovenantData MAX_VAULT_KEYS MAX_VAULT_WHITELIST_ENTRIES at h
  -- §1 size guard
  split at h
  · simp only [Bind.bind, Except.bind, throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
  · dsimp only [Bind.bind, Except.bind, Pure.pure, Except.pure,
               throwThe, MonadExcept.throw, MonadExceptOf.throw] at h
    -- §2 keyCount bounds guard
    split at h
    · simp at h
    · -- §3 threshold bounds guard
      split at h
      · simp at h
      · -- threshold guard passed: ¬(threshold < 1 ∨ threshold > keyCount)
        rename_i h_size h_kc h_th
        -- traverse remaining code: forIn(keys), sorted, size, wlCount, sizeMatch, forIn(wl), sorted, contains
        -- traverse remaining guards/loops via repeated split at h
        -- each rejection branch closes with simp at h
        split at h; · simp at h
        · split at h; · simp at h
          · split at h; · simp at h
            · split at h; · simp at h
              · split at h; · simp at h
                · split at h; · simp at h
                  · split at h; · simp at h
                    · split at h; · simp at h
                      · -- final .ok branch
                        cases h
                        simp_all [Nat.not_lt]
                        constructor <;> omega

end RubinFormal
