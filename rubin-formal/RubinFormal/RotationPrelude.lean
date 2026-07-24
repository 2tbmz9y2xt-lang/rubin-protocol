/-
  RubinFormal/RotationPrelude.lean — Suite-Registry Model & Pre-Rotation Audit Inventory

  Q-FORMAL-ROTATION-00: prerequisite for Q-FORMAL-ROTATION-01..05.

  ## Purpose

  This file introduces the abstract suite-registry model that rotation
  proofs (FI-ROT-01 … FI-ROT-07) will use, and documents which existing
  definitions / theorems carry hardcoded SUITE_ID_ML_DSA_87 assumptions.

  ## Pre-Rotation Scoping Convention

  Every definition or theorem that assumes a single-suite world (only
  SENTINEL + ML_DSA_87) is tagged with:

    /-- **Pre-rotation scope**: assumes single native suite ML-DSA-87.
        Must be generalised or re-proved under suite-registry model
        for Q-FORMAL-ROTATION-0N. -/

  ## Suite-Registry Model (abstract)

  After rotation activation, the consensus rule is:
    ∀ h, NATIVE_CREATE_SUITES(h) ⊆ NATIVE_SPEND_SUITES(h) ⊆ Registry
  where Registry maps suite_id →
    (semantic_id, PUBKEY_BYTES, SIG_BYTES, VERIFY_COST, binding_profile).

  The single-suite era is the special case where:
    Registry = { 0x01 ↦ ("ml-dsa-87", 2592, 4627, 8, "native-v1-raw-digest32") }
    NATIVE_CREATE_SUITES(h) = NATIVE_SPEND_SUITES(h) = {0x01}  ∀ h
-/

import RubinFormal.OutputDescriptorV2

namespace RubinFormal

namespace Rotation

/-! ### Abstract suite-registry types -/

/-- A single entry in the native suite registry. -/
structure SuiteEntry where
  suiteId      : Nat
  semanticId   : String
  pubkeyBytes  : Nat
  sigBytes     : Nat
  verifyCost   : Nat
  bindingProfile : String
  deriving Repr, DecidableEq

/-- The suite registry: a list of registered native suites.
    In the single-suite era this contains exactly one entry (ML-DSA-87). -/
def SuiteRegistry := List SuiteEntry

/-- Height-dependent active suite sets (post-rotation model). -/
structure RotationDescriptor where
  oldSuite : Nat
  newSuite : Nat
  h1       : Nat   -- NATIVE_CREATE_SUITES cutoff
  h2       : Nat   -- NATIVE_CREATE_SUITES + SPEND transition
  h4       : Option Nat  -- old-suite sunset (None = never)
  deriving Repr, DecidableEq

/-- Lookup a suite entry by ID in the registry. -/
def registryLookup (reg : SuiteRegistry) (sid : Nat) : Option SuiteEntry :=
  reg.find? (fun e => e.suiteId == sid)

/-- A suite_id is registered if `registryLookup` returns `some`. -/
def isRegistered (reg : SuiteRegistry) (sid : Nat) : Prop :=
  ∃ entry, registryLookup reg sid = some entry

/-! ### Single-suite (pre-rotation) era constants -/

/-- The ML-DSA-87 registry entry, used throughout the pre-rotation codebase. -/
def ML_DSA_87_ENTRY : SuiteEntry :=
  { suiteId := 0x01
    semanticId := "ml-dsa-87"
    pubkeyBytes := 2592
    sigBytes := 4627
    verifyCost := 8
    bindingProfile := "native-v1-raw-digest32" }

/-- Pre-rotation registry: only ML-DSA-87 registered. -/
def PRE_ROTATION_REGISTRY : SuiteRegistry := [ML_DSA_87_ENTRY]

/-- Pre-rotation: NATIVE_CREATE_SUITES(h) = NATIVE_SPEND_SUITES(h) = {0x01} for all h. -/
def preRotationActiveSuites (_h : Nat) : List Nat := [0x01]

/-- Canonical byte encoding of a Section 4.1.1 native suite entry.
    Field order matches `NativeSuiteEntryBytes_v1` exactly.
    Fails closed when any fixed-width field or CompactSize-prefixed UTF-8
    length leaves the canonical byte domain. -/
def nativeSuiteEntryBytesV1? (entry : SuiteEntry) : Option Bytes := do
  let semanticBytes := entry.semanticId.toUTF8
  let bindingBytes := entry.bindingProfile.toUTF8
  if _hsid : entry.suiteId < 256 then
    if _hsem : semanticBytes.size < 18446744073709551616 then
      if _hpub : entry.pubkeyBytes < 4294967296 then
        if _hsig : entry.sigBytes < 4294967296 then
          if _hcost : entry.verifyCost < 4294967296 then
            if _hbind : bindingBytes.size < 18446744073709551616 then
              pure <|
                RubinFormal.bytes #[UInt8.ofNat entry.suiteId] ++
                  RubinFormal.WireEnc.compactSize semanticBytes.size ++
                  semanticBytes ++
                  RubinFormal.WireEnc.u32le entry.pubkeyBytes ++
                  RubinFormal.WireEnc.u32le entry.sigBytes ++
                  RubinFormal.WireEnc.u32le entry.verifyCost ++
                  RubinFormal.WireEnc.compactSize bindingBytes.size ++
                  bindingBytes
            else
              none
          else
            none
        else
          none
      else
        none
    else
      none
  else
    none

/-- Canonical SHA3-256 hash of a Section 4.1.1 native suite entry.
    Fails closed when the byte encoding is undefined. -/
def nativeSuiteEntryHashV1? (entry : SuiteEntry) : Option Bytes := do
  let payload <- nativeSuiteEntryBytesV1? entry
  pure (SHA3.sha3_256 payload)

/-! ### Inventory of hardcoded assumptions (from Q-FORMAL-ROTATION-00 audit)

  #### TxParseV2.lean
  - `parseWitnessItem`: now factors through `parseWitnessItemWithRegistry`
    with registry-derived pubkey/sig bounds for registered suites, separating
    unknown-suite parse rejection from registered-suite bad-bounds rejection.
    The live parser still specializes to `PRE_ROTATION_REGISTRY`, while suite
    activation remains enforced by spend/create gates rather than parse stage.

  #### TxWeightV2.lean
  - `parseWitnessItemForCounts`: same two-branch suite dispatch.
  - `WitnessSectionResult.mlCount`: named for ML-DSA-87;
    post-rotation becomes per-suite count or generic `knownSuiteCount`.
  - `txWeightAndStats`: `mlCount * VERIFY_COST_ML_DSA_87` —
    must become `Σ (suite, count) → count * registry[suite].verifyCost`.
    **Action for ROT-03**: prove `weight_suite_aware_correct`.

  #### CovenantGenesisV1.lean
  - `validateOutGenesis`: `suiteId != SUITE_ID_ML_DSA_87 → reject`.
    **Action for ROT-04**: generalise to `suiteId ∉ NATIVE_CREATE_SUITES(h) → reject`.

  #### UtxoApplyGenesisV1.lean
  - `validateP2PKSpendPreSig`: descriptor-aware live spend gate.
    `rotDesc? = none` keeps pre-rotation `{ML_DSA_87}`;
    `rotDesc? = some d` enforces `suite ∈ NATIVE_SPEND_SUITES(h,d)`.
  - `validateWitnessItemLengths`: ML-DSA-87 branch with hardcoded bounds.
    **Action for ROT-02/ROT-03**: lookup bounds from registry.
  - `validateThresholdSigSpendNoCrypto`: ML-DSA-87 branch.
    **Action for ROT-04**: same generalisation.
  - `sampleOwnerP2PKData`: `SUITE_ID_ML_DSA_87` byte prefix in sample data.
    **Action**: update samples if registry model changes output format.

  #### UtxoBasicV1.lean
  - `scanSingleInputStep`: descriptor-aware P2PK input gate.
    `rotDesc? = none` keeps pre-rotation `{ML_DSA_87}`;
    `rotDesc? = some d` enforces `suite ∈ NATIVE_SPEND_SUITES(h,d)`.

-/

end Rotation

end RubinFormal
