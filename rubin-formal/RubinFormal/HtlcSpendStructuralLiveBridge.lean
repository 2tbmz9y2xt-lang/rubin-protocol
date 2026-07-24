import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.BytesEqLemmas

namespace RubinFormal

namespace HtlcSpendStructuralLiveBridge

open RubinFormal
open RubinFormal.UtxoApplyGenesisV1
open RubinFormal.CovenantGenesisV1

/-- LIVE invariant: HTLC spend-side always reserves exactly two witness slots. -/
theorem htlc_witness_slots_fixed (covData : Bytes) :
    UtxoApplyGenesisV1.WITNESS_SLOTS CovenantGenesisV1.COV_TYPE_HTLC covData = .ok 2 := by
  unfold UtxoApplyGenesisV1.WITNESS_SLOTS
  change Except.ok 2 = Except.ok 2
  rfl

/-- LIVE dispatch bridge for the HTLC branch:
    once the entry is HTLC, the covenant parser succeeds, and the witness window
    has room for two slots, `dispatchCovenantValidation` routes to `.htlc` and
    advances the witness cursor by exactly two items. -/
theorem dispatch_htlc_ok_constrained
    (e : UtxoBasicV1.UtxoEntry)
    (tx : UtxoBasicV1.Tx)
    (wc height blockMtp : Nat)
    (c : CovenantGenesisV1.HtlcCovenant)
    (hType : e.covenantType = CovenantGenesisV1.COV_TYPE_HTLC)
    (hParse : CovenantGenesisV1.parseHtlcCovenantData e.covenantData = .ok c)
    (hBound : wc + 2 ≤ tx.witness.length) :
    UtxoApplyGenesisV1.dispatchCovenantValidation e tx wc height blockMtp =
      .ok (.htlc c (wc + 2)) := by
  unfold UtxoApplyGenesisV1.dispatchCovenantValidation
  rw [hType]
  simp [
    hParse,
    show CovenantGenesisV1.COV_TYPE_HTLC ≠ CovenantGenesisV1.COV_TYPE_P2PK by native_decide,
    show CovenantGenesisV1.COV_TYPE_HTLC ≠ CovenantGenesisV1.COV_TYPE_MULTISIG by native_decide,
    show CovenantGenesisV1.COV_TYPE_HTLC ≠ CovenantGenesisV1.COV_TYPE_VAULT by native_decide
  ]
  change (match Except.ok 2 with
    | Except.error err => Except.error err
    | Except.ok slots =>
      if slots = 2 then
        if tx.witness.length < wc + slots then Except.error "TX_ERR_PARSE"
        else Except.ok (CovenantDispatchReady.htlc c (wc + 2))
      else Except.error "TX_ERR_PARSE") = Except.ok (CovenantDispatchReady.htlc c (wc + 2))
  simp [Nat.not_lt.mpr hBound]

/-- Structural guard: the path witness item must use the sentinel suite.
    This parse rejection happens before any HTLC branch routing, timelock, or
    hash/key checks. -/
theorem non_sentinel_path_rejects_parse
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem sigItem : UtxoBasicV1.WitnessItem)
    (blockHeight blockMtp : Nat)
    (hSuite : pathItem.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL) :
    UtxoApplyGenesisV1.validateHTLCSpendNoCrypto c pathItem sigItem blockHeight blockMtp =
      .error "TX_ERR_PARSE" := by
  unfold UtxoApplyGenesisV1.validateHTLCSpendNoCrypto
  simp [hSuite]
  change (Except.error "TX_ERR_PARSE" : Except String Unit) = Except.error "TX_ERR_PARSE"
  rfl

/-- Claim-path structural parse guard:
    once the sentinel/path-shape guards pass and the branch selects `pathId=0`,
    a too-short claim prefix rejects with `TX_ERR_PARSE` before any key-binding
    or preimage/hash check is consulted. -/
theorem claim_short_prefix_rejects_parse
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem sigItem : UtxoBasicV1.WitnessItem)
    (blockHeight blockMtp : Nat)
    (hSuite : pathItem.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hPub : pathItem.pubkey.size = 32)
    (hNonEmpty : ¬ pathItem.signature.size < 1)
    (hPath0 : (pathItem.signature.get! 0).toNat = 0)
    (hShort : pathItem.signature.size < 3) :
    UtxoApplyGenesisV1.validateHTLCSpendNoCrypto c pathItem sigItem blockHeight blockMtp =
      .error "TX_ERR_PARSE" := by
  unfold UtxoApplyGenesisV1.validateHTLCSpendNoCrypto
  simp [Except.bind, hSuite, hPub, hNonEmpty, hPath0, hShort]
  change (Except.error "TX_ERR_PARSE" : Except String Unit) = Except.error "TX_ERR_PARSE"
  rfl

/-- Unknown path discriminant rejects with `TX_ERR_PARSE` after the common
    structural guards but before any refund timelock or cryptographic checks. -/
theorem unknown_path_rejects_parse
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem sigItem : UtxoBasicV1.WitnessItem)
    (blockHeight blockMtp pathId : Nat)
    (hSuite : pathItem.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hPub : pathItem.pubkey.size = 32)
    (hNonEmpty : ¬ pathItem.signature.size < 1)
    (hPath : (pathItem.signature.get! 0).toNat = pathId)
    (hNe0 : pathId ≠ 0)
    (hNe1 : pathId ≠ 1) :
    UtxoApplyGenesisV1.validateHTLCSpendNoCrypto c pathItem sigItem blockHeight blockMtp =
      .error "TX_ERR_PARSE" := by
  unfold UtxoApplyGenesisV1.validateHTLCSpendNoCrypto
  simp [Except.bind, hSuite, hPub, hNonEmpty, hPath, hNe0, hNe1]
  change (Except.error "TX_ERR_PARSE" : Except String Unit) = Except.error "TX_ERR_PARSE"
  rfl

/-- Refund path height-lock enforcement on the LIVE spend helper:
    once the refund branch is selected, `TX_ERR_TIMELOCK_NOT_MET` is raised
    before signature-suite or later key-binding checks. -/
theorem refund_height_timelock_precedes_sig_checks
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem sigItem : UtxoBasicV1.WitnessItem)
    (blockHeight blockMtp : Nat)
    (hSuite : pathItem.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hPub : pathItem.pubkey.size = 32)
    (hSize : pathItem.signature.size = 1)
    (hPath1 : (pathItem.signature.get! 0).toNat = 1)
    (hRefundKey : pathItem.pubkey = c.refundKeyId)
    (hMode : c.lockMode = CovenantGenesisV1.LOCK_MODE_HEIGHT)
    (hLt : blockHeight < c.lockValue) :
    UtxoApplyGenesisV1.validateHTLCSpendNoCrypto c pathItem sigItem blockHeight blockMtp =
      .error "TX_ERR_TIMELOCK_NOT_MET" := by
  have hRefundSize32 : c.refundKeyId.size = 32 := by
    simpa [hRefundKey] using hPub
  unfold UtxoApplyGenesisV1.validateHTLCSpendNoCrypto
  simp [Except.bind, hSuite, hPub, hSize, hPath1, hRefundKey, hRefundSize32, hMode, hLt, bytes_bne_self_false]
  change (Except.error "TX_ERR_TIMELOCK_NOT_MET" : Except String Unit) = Except.error "TX_ERR_TIMELOCK_NOT_MET"
  rfl

/-- Refund path timestamp-lock enforcement on the LIVE spend helper:
    for timestamp-locked HTLCs the same precedence holds on the real path. -/
theorem refund_timestamp_timelock_precedes_sig_checks
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem sigItem : UtxoBasicV1.WitnessItem)
    (blockHeight blockMtp : Nat)
    (hSuite : pathItem.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hPub : pathItem.pubkey.size = 32)
    (hSize : pathItem.signature.size = 1)
    (hPath1 : (pathItem.signature.get! 0).toNat = 1)
    (hRefundKey : pathItem.pubkey = c.refundKeyId)
    (hMode : c.lockMode ≠ CovenantGenesisV1.LOCK_MODE_HEIGHT)
    (hLt : blockMtp < c.lockValue) :
    UtxoApplyGenesisV1.validateHTLCSpendNoCrypto c pathItem sigItem blockHeight blockMtp =
      .error "TX_ERR_TIMELOCK_NOT_MET" := by
  have hRefundSize32 : c.refundKeyId.size = 32 := by
    simpa [hRefundKey] using hPub
  unfold UtxoApplyGenesisV1.validateHTLCSpendNoCrypto
  simp [Except.bind, hSuite, hPub, hSize, hPath1, hRefundKey, hRefundSize32, hMode, hLt, bytes_bne_self_false]
  change (Except.error "TX_ERR_TIMELOCK_NOT_MET" : Except String Unit) = Except.error "TX_ERR_TIMELOCK_NOT_MET"
  rfl

/-- Positive LIVE refund-path bridge:
    once the sentinel/path-shape guards, refund-key binding, timelock, and live
    signature-item structural checks all pass, the real spend helper accepts. -/
theorem refund_height_path_accepts
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem sigItem : UtxoBasicV1.WitnessItem)
    (blockHeight blockMtp : Nat)
    (hSuite : pathItem.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hPub : pathItem.pubkey.size = 32)
    (hSize : pathItem.signature.size = 1)
    (hPath1 : (pathItem.signature.get! 0).toNat = 1)
    (hRefundKey : pathItem.pubkey = c.refundKeyId)
    (hMode : c.lockMode = CovenantGenesisV1.LOCK_MODE_HEIGHT)
    (hGe : c.lockValue ≤ blockHeight)
    (hSigOk : UtxoApplyGenesisV1.validateWitnessItemLengths sigItem blockHeight = .ok ())
    (hSigHash : SHA3.sha3_256 sigItem.pubkey = c.refundKeyId) :
    UtxoApplyGenesisV1.validateHTLCSpendNoCrypto c pathItem sigItem blockHeight blockMtp =
      .ok () := by
  have hRefundSize32 : c.refundKeyId.size = 32 := by
    simpa [hRefundKey] using hPub
  unfold UtxoApplyGenesisV1.validateHTLCSpendNoCrypto
  simp [Except.bind, hSuite, hPub, hSize, hPath1, hRefundKey, hRefundSize32, hMode, hSigOk, hSigHash,
    bytes_bne_self_false, Nat.not_lt.mpr hGe]

/-- Positive LIVE refund-path bridge for timestamp mode:
    the real helper accepts once the timestamp timelock is satisfied and the
    later signature-item structural/hash guards also pass. -/
theorem refund_timestamp_path_accepts
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem sigItem : UtxoBasicV1.WitnessItem)
    (blockHeight blockMtp : Nat)
    (hSuite : pathItem.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hPub : pathItem.pubkey.size = 32)
    (hSize : pathItem.signature.size = 1)
    (hPath1 : (pathItem.signature.get! 0).toNat = 1)
    (hRefundKey : pathItem.pubkey = c.refundKeyId)
    (hMode : c.lockMode ≠ CovenantGenesisV1.LOCK_MODE_HEIGHT)
    (hGe : c.lockValue ≤ blockMtp)
    (hSigOk : UtxoApplyGenesisV1.validateWitnessItemLengths sigItem blockHeight = .ok ())
    (hSigHash : SHA3.sha3_256 sigItem.pubkey = c.refundKeyId) :
    UtxoApplyGenesisV1.validateHTLCSpendNoCrypto c pathItem sigItem blockHeight blockMtp =
      .ok () := by
  have hRefundSize32 : c.refundKeyId.size = 32 := by
    simpa [hRefundKey] using hPub
  unfold UtxoApplyGenesisV1.validateHTLCSpendNoCrypto
  simp [Except.bind, hSuite, hPub, hSize, hPath1, hRefundKey, hRefundSize32, hMode, hSigOk, hSigHash,
    bytes_bne_self_false, Nat.not_lt.mpr hGe]

end HtlcSpendStructuralLiveBridge

end RubinFormal
