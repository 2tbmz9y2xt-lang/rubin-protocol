import RubinFormal.SighashV1

/-!
# Sighash Assumption Bridge (§12)

Records the explicit reduction theorem for the remaining honest `digestV1`
ceiling: equal live outputs on distinct preimages would require a SHA3-256
collision.

This is assumption-backed, not universal: the theorem reduces digest equality
to SHA3 equality on distinct preimages but does not claim cryptographic
impossibility by itself.
-/

namespace RubinFormal

open SighashV1

/-- Explicit live preimage builder for `digestV1`, factored only so the
    assumption-backed reduction theorem can talk about distinct preimages
    directly instead of leaving the SHA3 premise implicit in prose. -/
def digestV1Preimage
    (core : SighashV1.TxCoreForSighash)
    (chainId : Bytes) (inputIndex inputValue : Nat) : Bytes :=
  let inp :=
    match core.inputs.get? inputIndex with
    | some x => x
    | none =>
        {
          prevTxid := ByteArray.empty
          prevVoutLE := ByteArray.empty
          sequenceLE := ByteArray.empty
        }
  let hashPrevouts :=
    SHA3.sha3_256 (SighashV1.concatBytes (core.inputs.map (fun i => i.prevTxid ++ i.prevVoutLE)))
  let hashSeq :=
    SHA3.sha3_256 (SighashV1.concatBytes (core.inputs.map (fun i => i.sequenceLE)))
  let hashOut :=
    SHA3.sha3_256 (SighashV1.concatBytes core.outputsRaw)
  SighashV1.sighashPrefix ++
    chainId ++
    SighashV1.u32le core.version ++
    RubinFormal.bytes #[core.txKind] ++
    SighashV1.u64le core.txNonce.toNat ++
    SighashV1.hashOfDA core.txKind ++
    hashPrevouts ++
    hashSeq ++
    SighashV1.u32le inputIndex ++
    inp.prevTxid ++
    inp.prevVoutLE ++
    SighashV1.u64le inputValue ++
    inp.sequenceLE ++
    hashOut ++
    SighashV1.u32le core.locktime ++
    RubinFormal.bytes #[0x01]

set_option maxHeartbeats 1000000 in
/-- On the live success path, `digestV1` is exactly SHA3-256 over the explicit
    executable preimage builder above. -/
theorem digestV1_ok_eq_sha3_preimage
    (tx chainId : Bytes) (inputIndex inputValue : Nat)
    (core : SighashV1.TxCoreForSighash)
    (hParse : SighashV1.parseTxCoreForSighash tx = .ok core)
    (hInBounds : inputIndex < core.inputs.length) :
    SighashV1.digestV1 tx chainId inputIndex inputValue =
      .ok (SHA3.sha3_256 (digestV1Preimage core chainId inputIndex inputValue)) := by
  unfold SighashV1.digestV1 digestV1Preimage
  rw [hParse]
  simp only [Except.bind, Bind.bind]
  rw [if_neg (by omega)]
  rfl

/-- Equal live `digestV1` outputs on two distinct executable preimages reduce
    to a SHA3-256 collision obligation. This is the honest assumption-backed
    ceiling for the digest side of §12. -/
theorem digestV1_output_collision_reduces_to_sha3_collision
    (tx₁ tx₂ chainId₁ chainId₂ : Bytes)
    (inputIndex₁ inputIndex₂ inputValue₁ inputValue₂ : Nat)
    (core₁ core₂ : SighashV1.TxCoreForSighash)
    (hParse₁ : SighashV1.parseTxCoreForSighash tx₁ = .ok core₁)
    (hParse₂ : SighashV1.parseTxCoreForSighash tx₂ = .ok core₂)
    (hInBounds₁ : inputIndex₁ < core₁.inputs.length)
    (hInBounds₂ : inputIndex₂ < core₂.inputs.length)
    (hDistinct :
      digestV1Preimage core₁ chainId₁ inputIndex₁ inputValue₁ ≠
      digestV1Preimage core₂ chainId₂ inputIndex₂ inputValue₂)
    (hDigestEq :
      SighashV1.digestV1 tx₁ chainId₁ inputIndex₁ inputValue₁ =
      SighashV1.digestV1 tx₂ chainId₂ inputIndex₂ inputValue₂) :
    SHA3.sha3_256 (digestV1Preimage core₁ chainId₁ inputIndex₁ inputValue₁) =
      SHA3.sha3_256 (digestV1Preimage core₂ chainId₂ inputIndex₂ inputValue₂) ∧
    digestV1Preimage core₁ chainId₁ inputIndex₁ inputValue₁ ≠
      digestV1Preimage core₂ chainId₂ inputIndex₂ inputValue₂ := by
  rw [digestV1_ok_eq_sha3_preimage tx₁ chainId₁ inputIndex₁ inputValue₁ core₁ hParse₁ hInBounds₁,
    digestV1_ok_eq_sha3_preimage tx₂ chainId₂ inputIndex₂ inputValue₂ core₂ hParse₂ hInBounds₂] at hDigestEq
  injection hDigestEq with hSha
  exact ⟨hSha, hDistinct⟩

end RubinFormal
