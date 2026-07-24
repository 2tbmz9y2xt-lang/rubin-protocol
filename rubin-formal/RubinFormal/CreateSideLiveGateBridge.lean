import RubinFormal.CovenantGenesisV1
import RubinFormal.NativeSpendCreateGate

namespace RubinFormal

namespace CreateSideLiveGateBridge

open CovenantGenesisV1
open NativeSpendCreateGate

/-- Runtime-exact P2PK create-side branch used by the descriptor-aware
    genesis validator.
    Ordering mirrors the live path:
    value/length structural guards first, then native create-suite gating.
    On suite-gate failure this live surface returns `TX_ERR_SIG_ALG_INVALID`,
    matching Go `ValidateTxCovenantsGenesis`; this intentionally differs from
    legacy `validateOutGenesis`, which still owns the older
    `TX_ERR_COVENANT_TYPE_INVALID` classification.
    `none` keeps the default-provider singleton fallback `{ML_DSA_87}`;
    `some d` lifts the descriptor-aware `NativeCreateSuites(h,d)` gate. -/
def validateP2PKCreateLiveBranch
    (out : TxOut)
    (blockHeight : Nat)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor) :
    Except String Unit :=
  if out.value == 0 then
    .error "TX_ERR_COVENANT_TYPE_INVALID"
  else if out.covenantData.size != MAX_P2PK_COVENANT_DATA then
    .error "TX_ERR_COVENANT_TYPE_INVALID"
  else if !NativeSpendCreateGate.liveCreateGateAllows rotDesc? blockHeight
      (out.covenantData.get! 0).toNat then
    .error "TX_ERR_SIG_ALG_INVALID"
  else
    .ok ()

/-- Post-rotation specialization of `validateP2PKCreateLiveBranch`. -/
def validateP2PKCreateWithRotation
    (out : TxOut)
    (blockHeight : Nat)
    (d : NativeSuiteRotation.RotationDeploymentDescriptor) :
    Except String Unit :=
  validateP2PKCreateLiveBranch out blockHeight (some d)

/-- Descriptor-aware output-level genesis validator matching the live
    runtime create path:
    P2PK outputs use the rotation-aware create gate, while every non-P2PK
    branch delegates unchanged to `validateOutGenesis`. This means the P2PK
    branch follows the newer `ValidateTxCovenantsGenesis` surface, while the
    remaining covenant types keep the legacy validator behavior verbatim. -/
def validateOutGenesisWithRotation
    (out : TxOut)
    (txKind : Nat)
    (blockHeight : Nat)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor) :
    Except String Unit :=
  if out.covenantType == COV_TYPE_P2PK then
    validateP2PKCreateLiveBranch out blockHeight rotDesc?
  else
    validateOutGenesis out txKind blockHeight

/-- The exact P2PK create-side live branch accepts iff all earlier structural
    guards pass and the committed suite is active in `NativeCreateSuites(h,d)`. -/
theorem validateP2PKCreateLiveBranch_some_ok_iff
    (d : NativeSuiteRotation.RotationDeploymentDescriptor)
    (out : TxOut)
    (blockHeight : Nat) :
    validateP2PKCreateLiveBranch out blockHeight (some d) = .ok () ↔
      out.value ≠ 0 ∧
      out.covenantData.size = MAX_P2PK_COVENANT_DATA ∧
      (out.covenantData.get! 0).toNat ∈ NativeSuiteRotation.NativeCreateSuites blockHeight d := by
  by_cases hValue : out.value = 0
  · simp [validateP2PKCreateLiveBranch, hValue]
  · by_cases hSize : out.covenantData.size = MAX_P2PK_COVENANT_DATA
    · cases hGate :
        NativeSpendCreateGate.liveCreateGateAllows (some d) blockHeight
          (out.covenantData.get! 0).toNat with
      | false =>
          have hNotMem :
              (out.covenantData.get! 0).toNat ∉
                NativeSuiteRotation.NativeCreateSuites blockHeight d :=
            (NativeSpendCreateGate.liveCreateGateAllows_some_false_iff d blockHeight
              (out.covenantData.get! 0).toNat).mp hGate
          simp [validateP2PKCreateLiveBranch, hValue, hSize, hGate, hNotMem]
      | true =>
          have hMem :
              (out.covenantData.get! 0).toNat ∈
                NativeSuiteRotation.NativeCreateSuites blockHeight d :=
            (NativeSpendCreateGate.liveCreateGateAllows_some_iff d blockHeight
              (out.covenantData.get! 0).toNat).mp hGate
          simp [validateP2PKCreateLiveBranch, hValue, hSize, hGate, hMem]
    · simp [validateP2PKCreateLiveBranch, hValue, hSize]

/-- Pre-rotation fallback branch of the exact live create validator:
    `.ok ()` iff the earlier structural guards pass and suiteId = ML-DSA-87. -/
theorem validateP2PKCreateLiveBranch_none_ok_iff
    (out : TxOut)
    (blockHeight : Nat) :
    validateP2PKCreateLiveBranch out blockHeight none = .ok () ↔
      out.value ≠ 0 ∧
      out.covenantData.size = MAX_P2PK_COVENANT_DATA ∧
      (out.covenantData.get! 0).toNat = RubinFormal.SUITE_ID_ML_DSA_87 := by
  by_cases hValue : out.value = 0
  · simp [validateP2PKCreateLiveBranch, hValue]
  · by_cases hSize : out.covenantData.size = MAX_P2PK_COVENANT_DATA
    · cases hGate :
        NativeSpendCreateGate.liveCreateGateAllows none blockHeight
          (out.covenantData.get! 0).toNat with
      | false =>
          have hNotSuite :
              (out.covenantData.get! 0).toNat ≠ RubinFormal.SUITE_ID_ML_DSA_87 := by
            intro hSuite
            have hAllow :
                NativeSpendCreateGate.liveCreateGateAllows none blockHeight
                  (out.covenantData.get! 0).toNat = true :=
              (NativeSpendCreateGate.liveCreateGateAllows_none_iff blockHeight
                (out.covenantData.get! 0).toNat).mpr hSuite
            rw [hGate] at hAllow
            cases hAllow
          simp [validateP2PKCreateLiveBranch, hValue, hSize,
            NativeSpendCreateGate.liveCreateGateAllows, hNotSuite]
      | true =>
          have hSuite :
              (out.covenantData.get! 0).toNat = RubinFormal.SUITE_ID_ML_DSA_87 :=
            (NativeSpendCreateGate.liveCreateGateAllows_none_iff blockHeight
              (out.covenantData.get! 0).toNat).mp hGate
          simp [validateP2PKCreateLiveBranch, hValue, hSize,
            NativeSpendCreateGate.liveCreateGateAllows, hSuite]
    · simp [validateP2PKCreateLiveBranch, hValue, hSize]

/-- On the descriptor-aware branch, once the same preceding structural guards
    as the live create path pass, an inactive create suite is rejected with
    `TX_ERR_SIG_ALG_INVALID`. -/
theorem validateP2PKCreateWithRotation_rejects_inactive_suite
    (d : NativeSuiteRotation.RotationDeploymentDescriptor)
    (out : TxOut)
    (blockHeight : Nat)
    (hValue : out.value ≠ 0)
    (hSize : out.covenantData.size = MAX_P2PK_COVENANT_DATA)
    (hNotMem : (out.covenantData.get! 0).toNat ∉ NativeSuiteRotation.NativeCreateSuites blockHeight d) :
    validateP2PKCreateWithRotation out blockHeight d =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  have hGate :
      NativeSpendCreateGate.liveCreateGateAllows (some d) blockHeight (out.covenantData.get! 0).toNat = false :=
    (NativeSpendCreateGate.liveCreateGateAllows_some_false_iff d blockHeight
      (out.covenantData.get! 0).toNat).mpr hNotMem
  unfold validateP2PKCreateWithRotation validateP2PKCreateLiveBranch
  simp [hValue, hSize, hGate]

/-- Descriptor-aware live P2PK create bridge:
    under the same structural preconditions as the real create path,
    `.ok ()` is equivalent to create-suite membership. -/
theorem validateP2PKCreateWithRotation_ok_constrained
    (d : NativeSuiteRotation.RotationDeploymentDescriptor)
    (out : TxOut)
    (blockHeight : Nat)
    (hValue : out.value ≠ 0)
    (hSize : out.covenantData.size = MAX_P2PK_COVENANT_DATA) :
    validateP2PKCreateWithRotation out blockHeight d = .ok () ↔
      (out.covenantData.get! 0).toNat ∈ NativeSuiteRotation.NativeCreateSuites blockHeight d := by
  constructor
  · intro hOk
    by_contra hNotMem
    have hErr :=
      validateP2PKCreateWithRotation_rejects_inactive_suite d out blockHeight hValue hSize hNotMem
    rw [hErr] at hOk
    cases hOk
  · intro hMem
    have hGate :
        NativeSpendCreateGate.liveCreateGateAllows (some d) blockHeight (out.covenantData.get! 0).toNat = true :=
      (NativeSpendCreateGate.liveCreateGateAllows_some_iff d blockHeight
        (out.covenantData.get! 0).toNat).mpr hMem
    unfold validateP2PKCreateWithRotation validateP2PKCreateLiveBranch
    simp [hValue, hSize, hGate]

/-- Non-P2PK create branches are unchanged: the rotation-aware validator
    delegates exactly to legacy `validateOutGenesis`. -/
theorem validateOutGenesisWithRotation_eq_validateOutGenesis_of_not_p2pk
    (out : TxOut)
    (txKind blockHeight : Nat)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor)
    (hType : out.covenantType ≠ COV_TYPE_P2PK) :
    validateOutGenesisWithRotation out txKind blockHeight rotDesc? =
      validateOutGenesis out txKind blockHeight := by
  unfold validateOutGenesisWithRotation
  simp [hType]

/-- Exact top-level descriptor-aware create-side bridge on the real live
    output validator:
    on the P2PK branch, `.ok ()` is equivalent to passing the same structural
    guards as the runtime plus create-suite membership in
    `NativeCreateSuites(h,d)`. -/
theorem validateOutGenesisWithRotation_some_p2pk_ok_iff
    (d : NativeSuiteRotation.RotationDeploymentDescriptor)
    (out : TxOut)
    (txKind blockHeight : Nat)
    (hType : out.covenantType = COV_TYPE_P2PK) :
    validateOutGenesisWithRotation out txKind blockHeight (some d) = .ok () ↔
      out.value ≠ 0 ∧
      out.covenantData.size = MAX_P2PK_COVENANT_DATA ∧
      (out.covenantData.get! 0).toNat ∈ NativeSuiteRotation.NativeCreateSuites blockHeight d := by
  simpa [validateOutGenesisWithRotation, hType] using
    validateP2PKCreateLiveBranch_some_ok_iff d out blockHeight

/-- Exact top-level descriptor-aware create-side rejection theorem:
    after the same earlier structural guards as the runtime P2PK branch,
    an inactive create suite is rejected with `TX_ERR_SIG_ALG_INVALID`. -/
theorem validateOutGenesisWithRotation_some_p2pk_rejects_inactive_suite
    (d : NativeSuiteRotation.RotationDeploymentDescriptor)
    (out : TxOut)
    (txKind blockHeight : Nat)
    (hType : out.covenantType = COV_TYPE_P2PK)
    (hValue : out.value ≠ 0)
    (hSize : out.covenantData.size = MAX_P2PK_COVENANT_DATA)
    (hNotMem : (out.covenantData.get! 0).toNat ∉ NativeSuiteRotation.NativeCreateSuites blockHeight d) :
    validateOutGenesisWithRotation out txKind blockHeight (some d) =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  unfold validateOutGenesisWithRotation
  simp [hType]
  exact validateP2PKCreateWithRotation_rejects_inactive_suite d out blockHeight hValue hSize hNotMem

/-- Exact top-level live pre-rotation fallback theorem:
    on the P2PK branch, `.ok ()` is equivalent to the same runtime
    structural guards plus the singleton fallback suite ML-DSA-87. -/
theorem validateOutGenesisWithRotation_none_p2pk_ok_iff
    (out : TxOut)
    (txKind blockHeight : Nat)
    (hType : out.covenantType = COV_TYPE_P2PK) :
    validateOutGenesisWithRotation out txKind blockHeight none = .ok () ↔
      out.value ≠ 0 ∧
      out.covenantData.size = MAX_P2PK_COVENANT_DATA ∧
      (out.covenantData.get! 0).toNat = RubinFormal.SUITE_ID_ML_DSA_87 := by
  simpa [validateOutGenesisWithRotation, hType] using
    validateP2PKCreateLiveBranch_none_ok_iff out blockHeight

/-- Exact top-level live pre-rotation fallback rejection theorem:
    once the earlier P2PK structural guards pass, a non-ML-DSA-87 suite
    is rejected with `TX_ERR_SIG_ALG_INVALID`. -/
theorem validateOutGenesisWithRotation_none_p2pk_rejects_non_ml_dsa_87
    (out : TxOut)
    (txKind blockHeight : Nat)
    (hType : out.covenantType = COV_TYPE_P2PK)
    (hValue : out.value ≠ 0)
    (hSize : out.covenantData.size = MAX_P2PK_COVENANT_DATA)
    (hSuite : (out.covenantData.get! 0).toNat ≠ RubinFormal.SUITE_ID_ML_DSA_87) :
    validateOutGenesisWithRotation out txKind blockHeight none =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  have hGate :
      NativeSpendCreateGate.liveCreateGateAllows none blockHeight
        (out.covenantData.get! 0).toNat = false := by
    simp [NativeSpendCreateGate.liveCreateGateAllows, hSuite]
  unfold validateOutGenesisWithRotation validateP2PKCreateLiveBranch
  simp [hType, hValue, hSize, hGate]

end CreateSideLiveGateBridge

end RubinFormal
