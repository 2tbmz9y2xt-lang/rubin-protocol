import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.BytesEqLemmas

namespace RubinFormal

namespace HtlcSpendCryptoAssumptionBridge

open RubinFormal
open RubinFormal.UtxoApplyGenesisV1
open RubinFormal.CovenantGenesisV1

/-- Executable claim-path preimage length parser from the live HTLC spend path. -/
def claimPathPreLen (pathItem : UtxoBasicV1.WitnessItem) : Nat :=
  if pathItem.signature.size < 3 then
    0
  else
    UtxoApplyGenesisV1.parseU16le (pathItem.signature.get! 1) (pathItem.signature.get! 2)

/-- Executable claim-path selector byte from the live HTLC spend path.
    Returns `0xff` when the signature is empty so downstream helpers stay total. -/
def claimPathSelector (pathItem : UtxoBasicV1.WitnessItem) : Nat :=
  if pathItem.signature.size < 1 then
    0xff
  else
    (pathItem.signature.get! 0).toNat

/-- Executable claim-path preimage slicer from the live HTLC spend path. -/
def claimPathPreimage (pathItem : UtxoBasicV1.WitnessItem) : Bytes :=
  let preLen := claimPathPreLen pathItem
  if pathItem.signature.size != 3 + preLen then
    ByteArray.empty
  else
    pathItem.signature.extract 3 (3 + preLen)

/-- Extracted live claim-path hashlock helper:
    this is exactly the HTLC claim sub-branch, including the `pathId = 0x00`
    selector guard, between HTLC path dispatch and the later shared
    `sigItem` checks. -/
def validateHTLCClaimHashlock
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem : UtxoBasicV1.WitnessItem) : Except String Bytes := do
  if pathItem.signature.size < 3 then
    throw "TX_ERR_PARSE"
  if claimPathSelector pathItem != 0x00 then
    throw "TX_ERR_PARSE"
  let preLen := claimPathPreLen pathItem
  if preLen == 0 then
    throw "TX_ERR_PARSE"
  if preLen > 256 then
    throw "TX_ERR_PARSE"
  if pathItem.signature.size != 3 + preLen then
    throw "TX_ERR_PARSE"
  if pathItem.pubkey != c.claimKeyId then
    throw "TX_ERR_SIG_INVALID"
  let preimage := claimPathPreimage pathItem
  if SHA3.sha3_256 preimage != c.hash then
    throw "TX_ERR_SIG_INVALID"
  pure c.claimKeyId

set_option maxHeartbeats 10000000 in
theorem validateHTLCClaimHashlock_hash_mismatch_rejects_sig_invalid
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem : UtxoBasicV1.WitnessItem)
    (hPath0 : claimPathSelector pathItem = 0x00)
    (hPrePos : 0 < claimPathPreLen pathItem)
    (hPreBound : claimPathPreLen pathItem ≤ 256)
    (hSigSize : pathItem.signature.size = 3 + claimPathPreLen pathItem)
    (hClaimKey : pathItem.pubkey = c.claimKeyId)
    (hHashNe : SHA3.sha3_256 (claimPathPreimage pathItem) ≠ c.hash) :
    validateHTLCClaimHashlock c pathItem =
      .error "TX_ERR_SIG_INVALID" := by
  have hNotShort : ¬ pathItem.signature.size < 3 := by
    rw [hSigSize]
    omega
  have hPathOk : (claimPathSelector pathItem != 0x00) = false := by
    simp [bne_iff_ne, hPath0]
  have hPreNeZero : (claimPathPreLen pathItem == 0) = false := by
    simp [beq_iff_eq, Nat.ne_of_gt hPrePos]
  have hPreNotGt : ¬ claimPathPreLen pathItem > 256 := by
    omega
  have hSigSizeOk : (pathItem.signature.size != 3 + claimPathPreLen pathItem) = false := by
    simp [bne_iff_ne, hSigSize]
  have hClaimKeyFalse : (pathItem.pubkey != c.claimKeyId) = false := by
    rw [hClaimKey]
    exact bytes_bne_self_false c.claimKeyId
  have hHashTrue : (SHA3.sha3_256 (claimPathPreimage pathItem) != c.hash) = true := by
    exact bytes_bne_true_of_ne _ _ hHashNe
  unfold validateHTLCClaimHashlock
  simp only [Except.bind, hNotShort, hPathOk, hPreNeZero, hPreNotGt, hSigSizeOk,
    hClaimKeyFalse, hHashTrue, ite_false, ite_true]
  rfl

theorem validateHTLCClaimHashlock_ok_implies_hash_match
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem : UtxoBasicV1.WitnessItem)
    (hPath0 : claimPathSelector pathItem = 0x00)
    (hPrePos : 0 < claimPathPreLen pathItem)
    (hPreBound : claimPathPreLen pathItem ≤ 256)
    (hSigSize : pathItem.signature.size = 3 + claimPathPreLen pathItem)
    (hClaimKey : pathItem.pubkey = c.claimKeyId)
    (hOk : validateHTLCClaimHashlock c pathItem = .ok c.claimKeyId) :
    SHA3.sha3_256 (claimPathPreimage pathItem) = c.hash := by
  by_contra hHashNe
  have hErr :=
    validateHTLCClaimHashlock_hash_mismatch_rejects_sig_invalid c pathItem
      hPath0 hPrePos hPreBound hSigSize hClaimKey hHashNe
  rw [hErr] at hOk
  cases hOk

set_option maxHeartbeats 200000

/-- Honest assumption-boundary reduction for HTLC claim-path crypto:
    two distinct executable claim-path preimages cannot both satisfy the same
    extracted hashlock helper unless SHA3-256 collides on distinct inputs.
    This is a reduction theorem, not a cryptographic impossibility proof. -/
theorem claim_hash_collision_reduces_to_sha3_collision
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem₁ pathItem₂ : UtxoBasicV1.WitnessItem)
    (hPath0₁ : claimPathSelector pathItem₁ = 0x00)
    (hPrePos₁ : 0 < claimPathPreLen pathItem₁)
    (hPreBound₁ : claimPathPreLen pathItem₁ ≤ 256)
    (hSigSize₁ : pathItem₁.signature.size = 3 + claimPathPreLen pathItem₁)
    (hClaimKey₁ : pathItem₁.pubkey = c.claimKeyId)
    (hOk₁ : validateHTLCClaimHashlock c pathItem₁ = .ok c.claimKeyId)
    (hPath0₂ : claimPathSelector pathItem₂ = 0x00)
    (hPrePos₂ : 0 < claimPathPreLen pathItem₂)
    (hPreBound₂ : claimPathPreLen pathItem₂ ≤ 256)
    (hSigSize₂ : pathItem₂.signature.size = 3 + claimPathPreLen pathItem₂)
    (hClaimKey₂ : pathItem₂.pubkey = c.claimKeyId)
    (hOk₂ : validateHTLCClaimHashlock c pathItem₂ = .ok c.claimKeyId)
    (hDistinct : claimPathPreimage pathItem₁ ≠ claimPathPreimage pathItem₂) :
    SHA3.sha3_256 (claimPathPreimage pathItem₁) =
      SHA3.sha3_256 (claimPathPreimage pathItem₂) ∧
    claimPathPreimage pathItem₁ ≠ claimPathPreimage pathItem₂ := by
  have hHash₁ :
      SHA3.sha3_256 (claimPathPreimage pathItem₁) = c.hash :=
    validateHTLCClaimHashlock_ok_implies_hash_match c pathItem₁
      hPath0₁ hPrePos₁ hPreBound₁ hSigSize₁ hClaimKey₁ hOk₁
  have hHash₂ :
      SHA3.sha3_256 (claimPathPreimage pathItem₂) = c.hash :=
    validateHTLCClaimHashlock_ok_implies_hash_match c pathItem₂
      hPath0₂ hPrePos₂ hPreBound₂ hSigSize₂ hClaimKey₂ hOk₂
  constructor
  · calc
      SHA3.sha3_256 (claimPathPreimage pathItem₁) = c.hash := hHash₁
      _ = SHA3.sha3_256 (claimPathPreimage pathItem₂) := hHash₂.symm
  · exact hDistinct

end HtlcSpendCryptoAssumptionBridge

end RubinFormal
