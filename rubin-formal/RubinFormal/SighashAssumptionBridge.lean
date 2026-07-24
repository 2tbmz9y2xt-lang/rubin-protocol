import RubinFormal.ConnectBlockFull

/-!
# Sighash Assumption Bridge (§12/§14)

Closes the remaining honest ceiling gap for `sighash_v1`:

- LIVE bridge the TxContext `allowed_sighash_set` gate wired through
  `validateTxContextSighashGate` / `validateTxContextSighashWitness`
- explicit reduction theorem: equal live `digestV1` outputs on distinct
  preimages would require a SHA3-256 collision

This is assumption-backed, not universal: the theorem reduces digest equality
to SHA3 equality on distinct preimages but does not claim cryptographic
impossibility by itself.
-/

namespace RubinFormal

open SighashV1

/-- `validateTxContextSighashGate` succeeds exactly on the live allowlist
    predicate already proved exhaustive in `SighashV1.checkSighashPolicy`. -/
theorem validateTxContextSighashGate_ok_iff
    (allowedSet sighashType : UInt8) :
    validateTxContextSighashGate allowedSet sighashType = .ok () ↔
      SighashV1.checkSighashPolicy allowedSet sighashType = true := by
  constructor
  · intro hOk
    by_cases hPolicy : SighashV1.checkSighashPolicy allowedSet sighashType = true
    · exact hPolicy
    · have hPolicyFalse : SighashV1.checkSighashPolicy allowedSet sighashType = false := by
        cases hCheck : SighashV1.checkSighashPolicy allowedSet sighashType <;>
          simp [hCheck] at hPolicy ⊢
      cases hType : SighashV1.hasValidBaseType sighashType <;>
        simp [validateTxContextSighashGate, hType, hPolicyFalse] at hOk
  · intro hPolicy
    have hValid : SighashV1.hasValidBaseType sighashType = true := by
      cases hType : SighashV1.hasValidBaseType sighashType with
      | false =>
          simp [SighashV1.checkSighashPolicy, hType] at hPolicy
      | true =>
          rfl
    simp [validateTxContextSighashGate, hValid, hPolicy]

/-- Invalid base types are rejected before the allowlist branch runs. -/
theorem validateTxContextSighashGate_invalid_base_rejects
    (allowedSet sighashType : UInt8)
    (hInvalid : SighashV1.hasValidBaseType sighashType = false) :
    validateTxContextSighashGate allowedSet sighashType =
      .error "TX_ERR_SIGHASH_TYPE_INVALID" := by
  simp [validateTxContextSighashGate, hInvalid]

/-- Valid base types that still fail the allowlist map to
    `TX_ERR_SIG_ALG_INVALID`, preserving the live error ordering. -/
theorem validateTxContextSighashGate_disallowed_rejects
    (allowedSet sighashType : UInt8)
    (hValid : SighashV1.hasValidBaseType sighashType = true)
    (hDisallowed : SighashV1.checkSighashPolicy allowedSet sighashType = false) :
    validateTxContextSighashGate allowedSet sighashType =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  simp [validateTxContextSighashGate, hValid, hDisallowed]

/-- Non-empty witness signatures expose their last byte as the live sighash
    discriminator consumed by the TxContext gate. -/
theorem extractTxContextSighashType_ok
    (w : UtxoBasicV1.WitnessItem)
    (hNonEmpty : 0 < w.signature.size) :
    extractTxContextSighashType w =
      .ok (w.signature.get! (w.signature.size - 1)) := by
  have hNonZero : w.signature.size ≠ 0 := Nat.ne_of_gt hNonEmpty
  simp [extractTxContextSighashType, hNonZero]

/-- Empty signatures are rejected before any sighash-policy logic runs. -/
theorem validateTxContextSighashWitness_empty_signature_rejects
    (allowedSet : UInt8) (w : UtxoBasicV1.WitnessItem)
    (hEmpty : w.signature.size = 0) :
    validateTxContextSighashWitness allowedSet w =
      .error "TX_ERR_SIG_INVALID" := by
  simp [validateTxContextSighashWitness, extractTxContextSighashType, hEmpty]

/-- The witness-wired TxContext gate succeeds exactly when the last witness
    byte passes the live `allowed_sighash_set` policy. -/
theorem validateTxContextSighashWitness_ok_iff
    (allowedSet : UInt8) (w : UtxoBasicV1.WitnessItem)
    (hNonEmpty : 0 < w.signature.size) :
    validateTxContextSighashWitness allowedSet w = .ok () ↔
      SighashV1.checkSighashPolicy allowedSet
        (w.signature.get! (w.signature.size - 1)) = true := by
  simp [validateTxContextSighashWitness, extractTxContextSighashType_ok, hNonEmpty,
    validateTxContextSighashGate_ok_iff]

/-- Empty signatures fail before base-type and allowlist rejection paths. -/
theorem validateTxContextSighashWitness_invalid_base_rejects
    (allowedSet : UInt8) (w : UtxoBasicV1.WitnessItem)
    (hNonEmpty : 0 < w.signature.size)
    (hInvalid : SighashV1.hasValidBaseType
      (w.signature.get! (w.signature.size - 1)) = false) :
    validateTxContextSighashWitness allowedSet w =
      .error "TX_ERR_SIGHASH_TYPE_INVALID" := by
  simpa [validateTxContextSighashWitness, extractTxContextSighashType_ok, hNonEmpty] using
    (validateTxContextSighashGate_invalid_base_rejects
      allowedSet (w.signature.get! (w.signature.size - 1)) hInvalid)

/-- Witness-carried sighash bytes with a valid base type but disallowed policy
    still map to `TX_ERR_SIG_ALG_INVALID`. -/
theorem validateTxContextSighashWitness_disallowed_rejects
    (allowedSet : UInt8) (w : UtxoBasicV1.WitnessItem)
    (hNonEmpty : 0 < w.signature.size)
    (hValid : SighashV1.hasValidBaseType
      (w.signature.get! (w.signature.size - 1)) = true)
    (hDisallowed : SighashV1.checkSighashPolicy allowedSet
      (w.signature.get! (w.signature.size - 1)) = false) :
    validateTxContextSighashWitness allowedSet w =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  simpa [validateTxContextSighashWitness, extractTxContextSighashType_ok, hNonEmpty] using
    (validateTxContextSighashGate_disallowed_rejects
      allowedSet (w.signature.get! (w.signature.size - 1)) hValid hDisallowed)

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
