import RubinFormal.UtxoBasicV1
import RubinFormal.PrimitiveEncodingRoundtrip
import RubinFormal.CriticalInvariants

namespace RubinFormal
open UtxoBasicV1

/-- parseTx deterministic on nonce. -/
theorem parseTx_nonce_deterministic (txBytes : Bytes)
    (tx1 tx2 : Tx) (h1 : parseTx txBytes = .ok tx1) (h2 : parseTx txBytes = .ok tx2) :
    tx1.txNonce = tx2.txNonce := by rw [h1] at h2; cases h2; rfl

/-- u64le encoding of 0 differs from 1 — nonce encoding is non-constant. -/
theorem u64le_zero_ne_one : encodeU64le 0 ≠ encodeU64le 1 := by native_decide

/-- u64le encoding of 0 differs from max — covers full range. -/
theorem u64le_zero_ne_max : encodeU64le 0 ≠ encodeU64le 18446744073709551615 := by native_decide

/-- Parsing the same transaction bytes twice yields the same nonce, and a
    duplicate nonce pair is therefore not replay-free. This ties the live
    `parseTx` surface to the structural replay-domain invariant. -/
theorem parsed_nonce_duplicate_not_replay_free (txBytes : Bytes)
    (tx1 tx2 : Tx) (h1 : parseTx txBytes = .ok tx1) (h2 : parseTx txBytes = .ok tx2) :
    ¬ nonceReplayFree [tx1.txNonce, tx2.txNonce] := by
  have hNonce : tx1.txNonce = tx2.txNonce := parseTx_nonce_deterministic txBytes tx1 tx2 h1 h2
  have hMem : tx1.txNonce ∈ [tx2.txNonce] := by
    simp [hNonce]
  simpa [hNonce] using duplicate_nonce_not_replay_free tx1.txNonce [tx2.txNonce] hMem

/-- Section-level replay-domain contract: duplicate parsed nonces collapse to the
    same replay-domain element and are therefore rejected by the structural
    `nonceReplayFree` invariant. -/
theorem replay_domain_nonce_contract (txBytes : Bytes)
    (tx1 tx2 : Tx) (h1 : parseTx txBytes = .ok tx1) (h2 : parseTx txBytes = .ok tx2) :
    tx1.txNonce = tx2.txNonce ∧ ¬ nonceReplayFree [tx1.txNonce, tx2.txNonce] := by
  refine ⟨parseTx_nonce_deterministic txBytes tx1 tx2 h1 h2, ?_⟩
  exact parsed_nonce_duplicate_not_replay_free txBytes tx1 tx2 h1 h2

end RubinFormal
