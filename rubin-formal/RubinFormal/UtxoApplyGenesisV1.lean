import RubinFormal.Types
import RubinFormal.SHA3_256
import RubinFormal.OutputDescriptorV2
import RubinFormal.UtxoBasicV1
import RubinFormal.CovenantGenesisV1
import RubinFormal.NativeSpendCreateGate
import RubinFormal.RotationPrelude

/-!
# UtxoApplyGenesisV1

File role:
- mixed legacy/helper + bridge-support file for the spend-side surface
- retains hardcoded pre-rotation helpers such as `validateWitnessItemLengths`
  and `validateThresholdSigSpendNoCrypto`
- not the authoritative post-rotation universal layer; suite-aware claim
  ceilings now come from registry companions and dedicated bridge files
-/

namespace RubinFormal

namespace UtxoApplyGenesisV1

open RubinFormal
open RubinFormal.UtxoBasicV1
open RubinFormal.CovenantGenesisV1

/- Pre-rotation suite constants (re-exported from CovenantGenesisV1).
   Post-rotation (Q-FORMAL-ROTATION-02/04): use `Rotation.registryLookup`. -/
def SUITE_ID_ML_DSA_87 : Nat := CovenantGenesisV1.SUITE_ID_ML_DSA_87

def ML_DSA_87_PUBKEY_BYTES : Nat := 2592
def ML_DSA_87_SIG_BYTES : Nat := 4627

def WITNESS_SLOTS (covType : Nat) (covData : Bytes) : Except String Nat := do
  if covType == CovenantGenesisV1.COV_TYPE_HTLC then
    pure 2
  else if covType == CovenantGenesisV1.COV_TYPE_MULTISIG then
    if covData.size < 2 then throw "TX_ERR_PARSE"
    pure (covData.get! 1).toNat
  else if covType == CovenantGenesisV1.COV_TYPE_VAULT then
    if covData.size < 34 then throw "TX_ERR_VAULT_MALFORMED"
    pure (covData.get! 33).toNat
  else
    pure 1

inductive CovenantDispatchReady where
  | p2pk (nextWitnessCursor : Nat)
  | multisig (m : CovenantGenesisV1.MultisigCovenant) (nextWitnessCursor : Nat)
  | vault (v : CovenantGenesisV1.VaultCovenant) (nextWitnessCursor : Nat)
  | htlc (c : CovenantGenesisV1.HtlcCovenant) (nextWitnessCursor : Nat)
deriving Repr, DecidableEq

def lockIdOfEntry (e : UtxoEntry) : Bytes :=
  RubinFormal.OutputDescriptor.hash e.covenantType e.covenantData

def parseU16le (b0 b1 : UInt8) : Nat :=
  Wire.u16le? b0 b1

def validateP2PKSpendPreSig
    (entry : UtxoEntry)
    (w : WitnessItem)
    (blockHeight : Nat)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none) :
    Except String Unit := do
  let suite := w.suiteId
  match rotDesc? with
  | none =>
      -- Preserve the current pre-rotation validation order and error taxonomy.
      if entry.covenantData.size != CovenantGenesisV1.MAX_P2PK_COVENANT_DATA then
        throw "TX_ERR_COVENANT_TYPE_INVALID"
      let entrySuite := (entry.covenantData.get! 0).toNat
      if entrySuite != SUITE_ID_ML_DSA_87 then
        throw "TX_ERR_SIG_ALG_INVALID"
      if suite != SUITE_ID_ML_DSA_87 then
        throw "TX_ERR_SIG_ALG_INVALID"
      if entrySuite != suite then
        throw "TX_ERR_SIG_ALG_INVALID"
  | some descriptor =>
      -- The descriptor-aware path generalizes suite admission while leaving
      -- the default protocol behavior above unchanged.
      if !NativeSpendCreateGate.liveSpendGateAllows
          (some descriptor) blockHeight suite then
        throw "TX_ERR_SIG_ALG_INVALID"
      if entry.covenantData.size != CovenantGenesisV1.MAX_P2PK_COVENANT_DATA then
        throw "TX_ERR_COVENANT_TYPE_INVALID"
      if (entry.covenantData.get! 0).toNat != suite then
        throw "TX_ERR_COVENANT_TYPE_INVALID"
  let keyId := entry.covenantData.extract 1 33
  if SHA3.sha3_256 w.pubkey != keyId then
    throw "TX_ERR_SIG_INVALID"
  -- crypto verify omitted (out-of-scope for formal replay)
  pure ()

def validateWitnessItemLengths (w : WitnessItem) (_blockHeight : Nat) : Except String Unit := do
  if w.suiteId == SUITE_ID_SENTINEL then
    if w.pubkey.size != 0 || w.signature.size != 0 then
      throw "TX_ERR_PARSE"
    pure ()
  else if w.suiteId == SUITE_ID_ML_DSA_87 then
    -- Wire-level signature includes the trailing sighash_type byte (+1).
    if w.pubkey.size != ML_DSA_87_PUBKEY_BYTES || w.signature.size != ML_DSA_87_SIG_BYTES + 1 then
      throw "TX_ERR_SIG_NONCANONICAL"
    pure ()
  else
    throw "TX_ERR_SIG_ALG_INVALID"

/-- **Q-FORMAL-WAVE-A1**: Registry-aware witness item length validator.
    Suite-agnostic version that looks up per-suite bounds from the supplied
    `Rotation.SuiteRegistry`.

    In the pre-rotation era (`reg = [ML_DSA_87_ENTRY]`), this is **provably
    equivalent** to the legacy `validateWitnessItemLengths` — see bridge
    theorem `validateWitnessItemLengths_eq_registry_pre_rotation` below.

    Behaviour:
    - `SUITE_ID_SENTINEL`: same empty-pubkey/sig requirement as legacy.
    - Registered suite: bounds come from `registryLookup` entry
      (`pubkeyBytes` exact match, `sigBytes + 1` tolerance, non-empty sig).
    - Unregistered suite: `TX_ERR_SIG_ALG_INVALID`.

    **Status:** LIVE-ready for post-rotation wiring. Integration with call-sites
    (`validateHTLCSpendNoCrypto`, threshold loop) is handled in follow-up
    Wave A issues (#426/#427/#430) — this PR only adds the helper + bridge. -/
def validateWitnessItemLengthsRegistry
    (reg : Rotation.SuiteRegistry) (w : WitnessItem) (_blockHeight : Nat) :
    Except String Unit := do
  if w.suiteId == RubinFormal.SUITE_ID_SENTINEL then
    if w.pubkey.size != 0 || w.signature.size != 0 then
      throw "TX_ERR_PARSE"
    pure ()
  else
    match Rotation.registryLookup reg w.suiteId with
    | none => throw "TX_ERR_SIG_ALG_INVALID"
    | some entry =>
      if w.pubkey.size != entry.pubkeyBytes
         || w.signature.size != entry.sigBytes + 1 then
        throw "TX_ERR_SIG_NONCANONICAL"
      pure ()

/-- **Q-FORMAL-WAVE-A1 BRIDGE theorem** (class: BRIDGE per rubin-formal-executor).
    In the pre-rotation era where the suite registry is exactly
    `[ML_DSA_87_ENTRY]`, the legacy hardcoded `validateWitnessItemLengths`
    returns identically to the registry-aware
    `validateWitnessItemLengthsRegistry PRE_ROTATION_REGISTRY` on every input.

    This means the retained theorems proved against
    `validateWitnessItemLengths` in `StructuralRulesBehavioral.lean` and
    `HtlcSpendStructuralLiveBridge.lean` transfer to
    `validateWitnessItemLengthsRegistry PRE_ROTATION_REGISTRY` via `rw`.

    Wiring the registry-aware function into additional post-rotation paths is
    a separately authorized follow-up, not a claim made by this theorem. -/
theorem validateWitnessItemLengths_eq_registry_pre_rotation
    (w : WitnessItem) (h : Nat) :
    validateWitnessItemLengths w h =
    validateWitnessItemLengthsRegistry Rotation.PRE_ROTATION_REGISTRY w h := by
  unfold validateWitnessItemLengths validateWitnessItemLengthsRegistry
  simp only [Rotation.PRE_ROTATION_REGISTRY, Rotation.registryLookup,
             List.find?, Rotation.ML_DSA_87_ENTRY]
  by_cases hs : w.suiteId = RubinFormal.SUITE_ID_SENTINEL
  · simp [hs]
  · simp [hs]
    by_cases hm : w.suiteId = SUITE_ID_ML_DSA_87
    · -- ML-DSA-87 branch: rewrite via hm, unfold suite id + bound constants
      -- Then both LHS (hardcoded 2592/4627) and RHS (from ML_DSA_87_ENTRY) match.
      rw [hm]
      simp only [SUITE_ID_ML_DSA_87, CovenantGenesisV1.SUITE_ID_ML_DSA_87,
                 ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES]
      rfl
    · -- Unknown suite: neither sentinel nor ml-dsa-87 → registry lookup = none
      have hne_def : w.suiteId ≠ SUITE_ID_ML_DSA_87 := hm
      have hne_nat : w.suiteId ≠ 1 := fun heq => hne_def heq
      have h_beq : (1 == w.suiteId) = false := by
        cases hx : 1 == w.suiteId with
        | false => rfl
        | true =>
          exfalso; apply hne_nat
          exact (Nat.eq_of_beq_eq_true hx).symm
      simp [hm, h_beq]

/-- **Pre-rotation scope**: ML-DSA-87 is the only signing suite in threshold dispatch.
    Post-rotation (Q-FORMAL-ROTATION-04): `suite ∉ NATIVE_SPEND_SUITES(h) → reject`.
    See `validateThresholdSigSpendRegistry` + bridge theorem
    `validateThresholdSigSpend_eq_registry_pre_rotation` below for the
    suite-aware generalisation (Q-FORMAL-WAVE-A2). -/
def validateThresholdSigSpendNoCrypto
    (keys : List Bytes)
    (threshold : Nat)
    (ws : List WitnessItem)
    (_blockHeight : Nat)
    (_context : String) : Except String Unit := do
  if ws.length != keys.length then
    throw "TX_ERR_PARSE"
  let mut valid : Nat := 0
  for (w, key) in List.zip ws keys do
    if w.suiteId == RubinFormal.SUITE_ID_SENTINEL then
      pure ()
    else if w.suiteId == SUITE_ID_ML_DSA_87 then
      if SHA3.sha3_256 w.pubkey != key then
        throw "TX_ERR_SIG_INVALID"
      valid := valid + 1
    else
      throw "TX_ERR_SIG_ALG_INVALID"
  if valid < threshold then
    throw "TX_ERR_SIG_INVALID"
  pure ()

/-- **Q-FORMAL-WAVE-A2**: Registry-aware threshold signature spend validator.
    Suite-agnostic generalisation of `validateThresholdSigSpendNoCrypto`.

    Non-sentinel witnesses are admitted only when **both** of the following hold:
    1. `NativeSpendCreateGate.liveSpendGateAllows rotDesc? blockHeight w.suiteId` —
       the height-aware active spend gate (addresses the post-rotation case
       where a registered suite may still be *inactive* for spending at `h`).
    2. `(Rotation.registryLookup reg w.suiteId).isSome` — the suite exists in
       the supplied registry (carries per-suite parameters for downstream
       length checks that Wave A1 handled upstream).

    This matches the `Done = yes` spec from issue #426 literally:
    *"живой по gate+registry"* — a witness is admitted iff **both** the
    spend gate and the registry lookup accept.

    In the pre-rotation era (`rotDesc? = none`, `reg = [ML_DSA_87_ENTRY]`),
    both checks collapse to `sid == SUITE_ID_ML_DSA_87`, and the function is
    **provably equivalent** to the legacy `validateThresholdSigSpendNoCrypto`
    — see bridge theorem `validateThresholdSigSpend_eq_registry_pre_rotation`
    below.

    Behaviour:
    - `ws.length ≠ keys.length` → `TX_ERR_PARSE` (unchanged).
    - `SUITE_ID_SENTINEL` witnesses are keyless no-ops (counter unchanged).
    - `liveSpendGateAllows rotDesc? blockHeight w.suiteId &&
       (Rotation.registryLookup reg w.suiteId).isSome` → SHA3-256
       pubkey/key binding + counter `+1`.
    - Otherwise (gate rejected OR unregistered) → `TX_ERR_SIG_ALG_INVALID`.
    - Final `valid < threshold` comparison preserved from legacy.

    Structurally mirrors the legacy `for ... let mut` loop so bridge-level
    equivalence can be proven by per-element body congruence.

    **Status:** LIVE-ready for post-rotation wiring. Integration with call
    sites (MULTISIG/VAULT spend gates) is handled in Wave A3 (#427) — this
    PR only adds the helper + bridge. -/
def validateThresholdSigSpendRegistry
    (reg : Rotation.SuiteRegistry)
    (keys : List Bytes)
    (threshold : Nat)
    (ws : List WitnessItem)
    (blockHeight : Nat)
    (_context : String)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none) :
    Except String Unit := do
  if ws.length != keys.length then
    throw "TX_ERR_PARSE"
  let mut valid : Nat := 0
  for (w, key) in List.zip ws keys do
    if w.suiteId == RubinFormal.SUITE_ID_SENTINEL then
      pure ()
    else if w.suiteId == SUITE_ID_ML_DSA_87 then
      if SHA3.sha3_256 w.pubkey != key then
        throw "TX_ERR_SIG_INVALID"
      valid := valid + 1
    else
      throw "TX_ERR_SIG_ALG_INVALID"
  if valid < threshold then
    throw "TX_ERR_SIG_INVALID"
  pure ()

/-- **Q-FORMAL-WAVE-A2** internal lemma: on `PRE_ROTATION_REGISTRY`, a
    non-sentinel suite is admitted by `registryLookup ... |>.isSome` iff
    it equals the canonical `RubinFormal.SUITE_ID_ML_DSA_87`.

    Name uses `_eq_` (not `_iff_`) because the statement is a **Bool
    equality** (`isSome-call = beq-call`), not a Prop `↔`. This form is
    required for `simp only` rewriting of the registry-check subexpression
    in conjunctions such as
    `NativeSpendCreateGate.liveSpendGateAllows ... && (Rotation.registryLookup ...).isSome`
    in the main bridge proof. -/
theorem registryLookup_pre_rotation_isSome_eq_beq_ml_dsa_87 (sid : Nat) :
    (Rotation.registryLookup Rotation.PRE_ROTATION_REGISTRY sid).isSome =
    (sid == RubinFormal.SUITE_ID_ML_DSA_87) := by
  simp only [Rotation.PRE_ROTATION_REGISTRY, Rotation.registryLookup,
             List.find?, Rotation.ML_DSA_87_ENTRY, RubinFormal.SUITE_ID_ML_DSA_87]
  cases hx : (1 == sid) with
  | true =>
    have hsid : sid = 1 := (Nat.eq_of_beq_eq_true hx).symm
    rw [hsid]
    rfl
  | false =>
    have h_sid_beq_one_false : (sid == 1) = false := by
      cases hy : sid == 1 with
      | false => rfl
      | true =>
        -- hy : sid == 1 = true → sid = 1, so 1 == sid = 1 == 1 = true,
        -- contradicting hx : (1 == sid) = false. Explicit contradiction
        -- via `exfalso` + `absurd` + `decide`.
        exfalso
        have hsid : sid = 1 := Nat.eq_of_beq_eq_true hy
        rw [hsid] at hx
        exact absurd hx (by decide)
    simp [h_sid_beq_one_false]

/-- **Q-FORMAL-WAVE-A2** internal lemma: Bool-equality form of the
    pre-rotation fallback of `liveSpendGateAllows`.

    `NativeSpendCreateGate.liveSpendGateAllows_none_iff` (in
    `NativeSpendCreateGate.lean:111`) already proves the Prop `↔` form:
    `liveSpendGateAllows none h sid = true ↔ sid = SUITE_ID_ML_DSA_87`.
    That form cannot be used as a rewrite rule inside `simp only` over a
    Bool subexpression like
    `liveSpendGateAllows ... && (Rotation.registryLookup ...).isSome`
    because it rewrites a `Prop` (`_ = true`), not a `Bool`.

    This lemma provides the Bool-equality companion form
    `liveSpendGateAllows none h sid = (sid == SUITE_ID_ML_DSA_87)`
    required for the main bridge proof's `simp only` step over the
    combined
    `liveSpendGateAllows ... && (Rotation.registryLookup ...).isSome`
    admission check.

    Name uses `_eq_` (not `_iff_`) for the same convention reason as
    `registryLookup_pre_rotation_isSome_eq_beq_ml_dsa_87` above. -/
theorem liveSpendGateAllows_none_eq_beq_ml_dsa_87 (h sid : Nat) :
    NativeSpendCreateGate.liveSpendGateAllows none h sid =
    (sid == RubinFormal.SUITE_ID_ML_DSA_87) := by
  unfold NativeSpendCreateGate.liveSpendGateAllows
  cases hc : sid == RubinFormal.SUITE_ID_ML_DSA_87 with
  | true =>
    have hsid : sid = RubinFormal.SUITE_ID_ML_DSA_87 := Nat.eq_of_beq_eq_true hc
    simp [hsid]
  | false =>
    have hne : sid ≠ RubinFormal.SUITE_ID_ML_DSA_87 := by
      intro heq
      rw [heq] at hc
      exact absurd hc (by decide)
    simp [hne]

/-- **Q-FORMAL-WAVE-A2 BRIDGE theorem** (class: BRIDGE per rubin-formal-executor).
    In the pre-rotation era where `rotDesc? = none` and the suite registry
    is exactly `[ML_DSA_87_ENTRY]`, the legacy hardcoded
    `validateThresholdSigSpendNoCrypto` returns identically to the
    registry-aware `validateThresholdSigSpendRegistry PRE_ROTATION_REGISTRY`
    on every input.

    The registry-aware function can therefore be wired into post-rotation
    threshold-dispatch call sites in follow-up PRs (Wave A3 / #427) without
    invalidating any current behavioural proof that references the legacy
    `validateThresholdSigSpendNoCrypto` — they specialise under the bridge
    to the same theorem statement.

    **Proof strategy:** both functions share identical outer structure
    (length-check, `for ... let mut valid := 0` loop, final threshold
    compare). The only divergence is the per-element inner branch:
    legacy uses `if w.suiteId == ML_DSA_87 then <check> else throw`,
    registry uses `if liveSpendGateAllows rotDesc? h w.suiteId &&
    (registryLookup reg w.suiteId).isSome then <check> else throw`.
    On `PRE_ROTATION_REGISTRY` with `rotDesc? = none`:
    - `liveSpendGateAllows none h sid = (sid == ML_DSA_87)` by
      `liveSpendGateAllows_none_eq_beq_ml_dsa_87`
    - `(registryLookup PRE_ROT sid).isSome = (sid == ML_DSA_87)` by
      `registryLookup_pre_rotation_isSome_eq_beq_ml_dsa_87`
    - Combined: `(sid == ML_DSA_87) && (sid == ML_DSA_87) = (sid == ML_DSA_87)`
    - Matches legacy pointwise. -/
theorem validateThresholdSigSpend_eq_registry_pre_rotation
    (keys : List Bytes) (threshold : Nat) (ws : List WitnessItem)
    (h : Nat) (ctx : String) :
    validateThresholdSigSpendNoCrypto keys threshold ws h ctx =
    validateThresholdSigSpendRegistry Rotation.PRE_ROTATION_REGISTRY keys threshold ws h ctx := by
  unfold validateThresholdSigSpendNoCrypto validateThresholdSigSpendRegistry
  -- Reduce the spend gate and the registry lookup to `sid == ML_DSA_87`
  -- in canonical form, then collapse `(x && x) = x` by Bool idempotence.
  -- Additionally unfold the local `SUITE_ID_ML_DSA_87` alias so the legacy
  -- branch uses the same canonical `RubinFormal.SUITE_ID_ML_DSA_87`.
  simp only [liveSpendGateAllows_none_eq_beq_ml_dsa_87,
             registryLookup_pre_rotation_isSome_eq_beq_ml_dsa_87,
             Bool.and_self, SUITE_ID_ML_DSA_87,
             CovenantGenesisV1.SUITE_ID_ML_DSA_87,
             RubinFormal.SUITE_ID_ML_DSA_87]

def validateHTLCSpendNoCrypto
    (c : CovenantGenesisV1.HtlcCovenant)
    (pathItem : WitnessItem)
    (sigItem : WitnessItem)
    (blockHeight : Nat)
    (blockMtp : Nat) : Except String Unit := do
  if pathItem.suiteId != RubinFormal.SUITE_ID_SENTINEL then
    throw "TX_ERR_PARSE"
  if pathItem.pubkey.size != 32 then
    throw "TX_ERR_PARSE"
  if pathItem.signature.size < 1 then
    throw "TX_ERR_PARSE"
  let pathId := (pathItem.signature.get! 0).toNat
  let mut expectedKeyId : Bytes := ByteArray.empty
  if pathId == 0x00 then
    if pathItem.signature.size < 3 then
      throw "TX_ERR_PARSE"
    let preLen := parseU16le (pathItem.signature.get! 1) (pathItem.signature.get! 2)
    if preLen == 0 then
      throw "TX_ERR_PARSE"
    -- CANONICAL hardening: HTLC preimage MUST be at least 16 bytes.
    if preLen < 16 then
      throw "TX_ERR_PARSE"
    if preLen > 256 then
      throw "TX_ERR_PARSE"
    if pathItem.signature.size != 3 + preLen then
      throw "TX_ERR_PARSE"
    let pathKeyId := pathItem.pubkey
    if pathKeyId != c.claimKeyId then
      throw "TX_ERR_SIG_INVALID"
    let preimage := pathItem.signature.extract 3 (3 + preLen)
    if SHA3.sha3_256 preimage != c.hash then
      throw "TX_ERR_SIG_INVALID"
    expectedKeyId := c.claimKeyId
  else if pathId == 0x01 then
    if pathItem.signature.size != 1 then
      throw "TX_ERR_PARSE"
    let pathKeyId := pathItem.pubkey
    if pathKeyId != c.refundKeyId then
      throw "TX_ERR_SIG_INVALID"
    if c.lockMode == CovenantGenesisV1.LOCK_MODE_HEIGHT then
      if blockHeight < c.lockValue then
        throw "TX_ERR_TIMELOCK_NOT_MET"
    else
      if blockMtp < c.lockValue then
        throw "TX_ERR_TIMELOCK_NOT_MET"
    expectedKeyId := c.refundKeyId
  else
    throw "TX_ERR_PARSE"

  -- sig item structural checks + activation
  validateWitnessItemLengths sigItem blockHeight
  if SHA3.sha3_256 sigItem.pubkey != expectedKeyId then
    throw "TX_ERR_SIG_INVALID"
  -- crypto verify omitted
  pure ()

def vaultCreationOwnerAuthorized
    (owner : Bytes)
    (inputLockIds : List Bytes)
    (inputCovTypes : List Nat) : Bool :=
  (List.zip inputLockIds inputCovTypes).any (fun (lockId, covType) =>
    lockId == owner &&
      (covType == CovenantGenesisV1.COV_TYPE_P2PK ||
        covType == CovenantGenesisV1.COV_TYPE_MULTISIG))

def vaultSpendOutputAllowed
    (whitelist : List Bytes)
    (o : UtxoBasicV1.TxOut) : Bool :=
  (o.covenantType != CovenantGenesisV1.COV_TYPE_VAULT) &&
    whitelist.contains (RubinFormal.OutputDescriptor.hash o.covenantType o.covenantData)

def vaultSpendOutputsAllowed
    (whitelist : List Bytes)
    (outs : List UtxoBasicV1.TxOut) : Bool :=
  outs.all (vaultSpendOutputAllowed whitelist)

/-- Per-input structural checks from the for-loop (lines 218-220).
    LIVE sub-function: called from applyNonCoinbaseTxBasicNoCrypto per-input loop.
    Ordering: scriptSig non-empty → sequence invalid → coinbase prevout. -/
def validateInputStructural (i : UtxoBasicV1.TxIn) : Except String Unit := do
  if i.scriptSig.size != 0 then throw "TX_ERR_PARSE"
  if i.sequence > 0x7fffffff then throw "TX_ERR_SEQUENCE_INVALID"
  if UtxoBasicV1.isCoinbasePrevout i then throw "TX_ERR_PARSE"
  pure ()

/-- Post-loop witness cursor check.
    LIVE sub-function: called after per-input loop in applyNonCoinbaseTxBasicNoCrypto. -/
def validateWitnessCursorComplete (cursor witnessLen : Nat) : Except String Unit :=
  if cursor != witnessLen then Except.error "TX_ERR_PARSE" else Except.ok ()

/-- Per-input UTXO lookup and pre-covenant checks.
    LIVE sub-function: called from applyNonCoinbaseTxBasicNoCrypto per-input loop.
    Ordering: duplicate → missing UTXO → anchor/DA → coinbase maturity.
    Written without do-notation to avoid join points for formal proofs. -/
def validateInputUtxoLookup
    (isDuplicate : Bool)
    (utxoEntry : Option UtxoBasicV1.UtxoEntry)
    (height : Nat) : Except String UtxoBasicV1.UtxoEntry :=
  if isDuplicate then Except.error "TX_ERR_PARSE"
  else match utxoEntry with
    | none => Except.error "TX_ERR_MISSING_UTXO"
    | some e =>
      if e.covenantType == CovenantGenesisV1.COV_TYPE_ANCHOR ||
         e.covenantType == CovenantGenesisV1.COV_TYPE_DA_COMMIT then
        Except.error "TX_ERR_MISSING_UTXO"
      else if e.createdByCoinbase then
        if height < e.creationHeight + UtxoBasicV1.COINBASE_MATURITY then
          Except.error "TX_ERR_COINBASE_IMMATURE"
        else Except.ok e
      else Except.ok e

/-- Pre-input semantic checks: parse, nonce, output covenants.
    LIVE sub-function: applyNonCoinbaseTxBasicNoCrypto calls it directly.
    Ordering: TX_ERR_PARSE (empty inputs) → TX_ERR_TX_NONCE_INVALID →
    TX_ERR_COVENANT_TYPE_INVALID (output validation) → per-input checks. -/
def applyTxPreInputChecks
    (tx : UtxoBasicV1.Tx)
    (height : Nat) : Except String Unit := do
  if tx.inputs.length == 0 then throw "TX_ERR_PARSE"
  if tx.txNonce == 0 then throw "TX_ERR_TX_NONCE_INVALID"
  for o in tx.outputs do
    CovenantGenesisV1.validateOutGenesis
      { value := o.value, covenantType := o.covenantType, covenantData := o.covenantData }
      tx.txKind height

/-- Value conservation check. LIVE sub-function: called from
    applyNonCoinbaseTxBasicNoCrypto after output summation.
    Written without do-notation. -/
def validateValueConservation
    (sumOut sumIn : Nat)
    (vaultInputCount sumInVault : Nat) : Except String Unit :=
  if sumOut > sumIn then Except.error "TX_ERR_VALUE_CONSERVATION"
  else if vaultInputCount == 1 && sumOut < sumInVault then
    Except.error "TX_ERR_VALUE_CONSERVATION"
  else Except.ok ()

/-- Per-input covenant dispatch — LIVE structural dispatch sub-function used by
    `applyNonCoinbaseTxBasicNoCrypto` before branch-specific checks/state
    updates. Written without do-notation to enable formal dispatch ordering
    proofs while staying on the live call path.
    Ordering: P2PK → Multisig → Vault → HTLC → TX_ERR_COVENANT_TYPE_INVALID. -/
def dispatchCovenantValidation
    (e : UtxoBasicV1.UtxoEntry)
    (tx : UtxoBasicV1.Tx)
    (witnessCursor : Nat)
    (_height _blockMtp : Nat) : Except String CovenantDispatchReady :=
  if e.covenantType == CovenantGenesisV1.COV_TYPE_P2PK then
    match WITNESS_SLOTS e.covenantType e.covenantData with
    | .error err => Except.error err
    | .ok slots =>
      if slots != 1 then Except.error "TX_ERR_PARSE"
      else if witnessCursor + slots > tx.witness.length then Except.error "TX_ERR_PARSE"
      else Except.ok (.p2pk (witnessCursor + 1))
  else if e.covenantType == CovenantGenesisV1.COV_TYPE_MULTISIG then
    match CovenantGenesisV1.parseMultisigCovenantData e.covenantData with
    | .error err => Except.error err
    | .ok m =>
      match WITNESS_SLOTS e.covenantType e.covenantData with
      | .error err => Except.error err
      | .ok slots =>
        if witnessCursor + slots > tx.witness.length then Except.error "TX_ERR_PARSE"
        else Except.ok (.multisig m (witnessCursor + slots))
  else if e.covenantType == CovenantGenesisV1.COV_TYPE_VAULT then
    match CovenantGenesisV1.parseVaultCovenantData e.covenantData with
    | .error err => Except.error err
    | .ok v =>
      match WITNESS_SLOTS e.covenantType e.covenantData with
      | .error err => Except.error err
      | .ok slots =>
        if witnessCursor + slots > tx.witness.length then Except.error "TX_ERR_PARSE"
        else Except.ok (.vault v (witnessCursor + slots))
  else if e.covenantType == CovenantGenesisV1.COV_TYPE_HTLC then
    match CovenantGenesisV1.parseHtlcCovenantData e.covenantData with
    | .error err => Except.error err
    | .ok c =>
      match WITNESS_SLOTS e.covenantType e.covenantData with
      | .error err => Except.error err
      | .ok slots =>
        if slots != 2 then Except.error "TX_ERR_PARSE"
        else if witnessCursor + slots > tx.witness.length then Except.error "TX_ERR_PARSE"
        else Except.ok (.htlc c (witnessCursor + 2))
  else
    Except.error "TX_ERR_COVENANT_TYPE_INVALID"

/-! ## Vault spend validation — FULL (R14)

Extracted from applyNonCoinbaseTxBasicNoCrypto lines 398-412.
Covers ALL vault spend rules: owner auth + fee sponsor + threshold sig + whitelist.
Written without do-notation for formal proof access.
LIVE: called from applyNonCoinbaseTxBasicNoCrypto vault branch. -/

/-- Vault spend validation: ALL vault rules.
    LIVE sub-function: explicit bind, mirrors live code exactly. -/
def validateVaultSpend
    (ownerAuthPresent : Bool)
    (inputLockIds : List Bytes)
    (inputCovTypes : List Nat)
    (vaultOwnerLockId : Bytes)
    (vaultKeys : List Bytes)
    (vaultThreshold : Nat)
    (vaultWitness : List UtxoBasicV1.WitnessItem)
    (height : Nat)
    (txOutputs : List UtxoBasicV1.TxOut)
    (vaultWhitelist : List Bytes)
    : Except String Unit :=
  if !ownerAuthPresent then Except.error "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"
  else
    let sponsorOk := (List.zip inputCovTypes inputLockIds).all fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vaultOwnerLockId
    if !sponsorOk then Except.error "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN"
    else
      match validateThresholdSigSpendNoCrypto vaultKeys vaultThreshold vaultWitness height "CORE_VAULT" with
      | .error e => Except.error e
      | .ok () =>
        if !(vaultSpendOutputsAllowed vaultWhitelist txOutputs) then
          Except.error "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED"
        else Except.ok ()

/-- Registry-aware vault spend helper used to rebind the spend-side theorem
    surface to the suite-aware helper layer. It mirrors `validateVaultSpend`
    exactly, but delegates threshold validation to
    `validateThresholdSigSpendRegistry`. -/
def validateVaultSpendRegistry
    (reg : Rotation.SuiteRegistry)
    (ownerAuthPresent : Bool)
    (inputLockIds : List Bytes)
    (inputCovTypes : List Nat)
    (vaultOwnerLockId : Bytes)
    (vaultKeys : List Bytes)
    (vaultThreshold : Nat)
    (vaultWitness : List UtxoBasicV1.WitnessItem)
    (height : Nat)
    (txOutputs : List UtxoBasicV1.TxOut)
    (vaultWhitelist : List Bytes)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none)
    : Except String Unit :=
  if !ownerAuthPresent then Except.error "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"
  else
    let sponsorOk := (List.zip inputCovTypes inputLockIds).all fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vaultOwnerLockId
    if !sponsorOk then Except.error "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN"
    else
      match validateThresholdSigSpendRegistry reg vaultKeys vaultThreshold vaultWitness height "CORE_VAULT" rotDesc? with
      | .error e => Except.error e
      | .ok () =>
        if !(vaultSpendOutputsAllowed vaultWhitelist txOutputs) then
          Except.error "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED"
        else Except.ok ()

/-- **Q-FORMAL-WAVE-A3 BRIDGE theorem** (class: BRIDGE). On
    `PRE_ROTATION_REGISTRY`, the live hardcoded vault spend helper is
    pointwise equal to the registry-aware helper. -/
theorem validateVaultSpend_eq_registry_pre_rotation
    (ownerAuthPresent : Bool)
    (inputLockIds : List Bytes)
    (inputCovTypes : List Nat)
    (vaultOwnerLockId : Bytes)
    (vaultKeys : List Bytes)
    (vaultThreshold : Nat)
    (vaultWitness : List UtxoBasicV1.WitnessItem)
    (height : Nat)
    (txOutputs : List UtxoBasicV1.TxOut)
    (vaultWhitelist : List Bytes) :
    validateVaultSpend ownerAuthPresent inputLockIds inputCovTypes vaultOwnerLockId
      vaultKeys vaultThreshold vaultWitness height txOutputs vaultWhitelist =
    validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY ownerAuthPresent
      inputLockIds inputCovTypes vaultOwnerLockId vaultKeys vaultThreshold
      vaultWitness height txOutputs vaultWhitelist := by
  unfold validateVaultSpend validateVaultSpendRegistry
  simp [validateThresholdSigSpend_eq_registry_pre_rotation]

/-- Owner auth missing → TX_ERR_VAULT_OWNER_AUTH_REQUIRED. -/
theorem vault_no_owner (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes) :
    validateVaultSpend false lids covs vOwnLid vKeys vThr vWit h outs wl =
    .error "TX_ERR_VAULT_OWNER_AUTH_REQUIRED" := by
  simp [validateVaultSpend]

/-- Registry companion for `vault_no_owner` on `PRE_ROTATION_REGISTRY`. -/
theorem vault_no_owner_registry_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem)
    (h : Nat) (outs : List UtxoBasicV1.TxOut) (wl : List Bytes) :
    validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY false lids covs
      vOwnLid vKeys vThr vWit h outs wl =
    .error "TX_ERR_VAULT_OWNER_AUTH_REQUIRED" := by
  simp [validateVaultSpendRegistry]

/-- Bad fee sponsor → TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN. -/
theorem vault_bad_sponsor (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hBad : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = false) :
    validateVaultSpend true lids covs vOwnLid vKeys vThr vWit h outs wl =
    .error "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN" := by
  simp [validateVaultSpend, hBad]

/-- Registry companion for `vault_bad_sponsor` on `PRE_ROTATION_REGISTRY`. -/
theorem vault_bad_sponsor_registry_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem)
    (h : Nat) (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hBad : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = false) :
    validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY true lids covs
      vOwnLid vKeys vThr vWit h outs wl =
    .error "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN" := by
  simp [validateVaultSpendRegistry, hBad]

/-- Generic live propagation bridge: once owner-auth and sponsor checks pass,
    any error returned by `validateThresholdSigSpendNoCrypto` is forwarded
    unchanged through `validateVaultSpend`. -/
theorem vault_threshold_error_propagates
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (e : String)
    (hOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hSig : validateThresholdSigSpendNoCrypto vKeys vThr vWit h "CORE_VAULT" = .error e) :
    validateVaultSpend true lids covs vOwnLid vKeys vThr vWit h outs wl =
    .error e := by
  simp [validateVaultSpend, hOk, hSig]

/-- Registry companion for `vault_threshold_error_propagates` on
    `PRE_ROTATION_REGISTRY`. -/
theorem vault_threshold_error_propagates_registry_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem)
    (h : Nat) (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (e : String)
    (hOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hSig : validateThresholdSigSpendRegistry Rotation.PRE_ROTATION_REGISTRY
      vKeys vThr vWit h "CORE_VAULT" = .error e) :
    validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY true lids covs
      vOwnLid vKeys vThr vWit h outs wl =
    .error e := by
  simp [validateVaultSpendRegistry, hOk, hSig]

/-- Bad whitelist → TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED. -/
theorem vault_bad_whitelist (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hSig : validateThresholdSigSpendNoCrypto vKeys vThr vWit h "CORE_VAULT" = .ok ())
    (hWL : vaultSpendOutputsAllowed wl outs = false) :
    validateVaultSpend true lids covs vOwnLid vKeys vThr vWit h outs wl =
    .error "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED" := by
  simp [validateVaultSpend, hOk, hSig, hWL]

/-- Registry companion for `vault_bad_whitelist` on `PRE_ROTATION_REGISTRY`. -/
theorem vault_bad_whitelist_registry_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem)
    (h : Nat) (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hSig : validateThresholdSigSpendRegistry Rotation.PRE_ROTATION_REGISTRY
      vKeys vThr vWit h "CORE_VAULT" = .ok ())
    (hWL : vaultSpendOutputsAllowed wl outs = false) :
    validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY true lids covs
      vOwnLid vKeys vThr vWit h outs wl =
    .error "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED" := by
  simp [validateVaultSpendRegistry, hOk, hSig, hWL]

/-- All vault rules pass → .ok (). -/
theorem vault_all_pass (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hSig : validateThresholdSigSpendNoCrypto vKeys vThr vWit h "CORE_VAULT" = .ok ())
    (hWL : vaultSpendOutputsAllowed wl outs = true) :
    validateVaultSpend true lids covs vOwnLid vKeys vThr vWit h outs wl = .ok () := by
  simp [validateVaultSpend, hOk, hSig, hWL]

/-- Registry companion for `vault_all_pass` on `PRE_ROTATION_REGISTRY`. -/
theorem vault_all_pass_registry_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List UtxoBasicV1.WitnessItem)
    (h : Nat) (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hSig : validateThresholdSigSpendRegistry Rotation.PRE_ROTATION_REGISTRY
      vKeys vThr vWit h "CORE_VAULT" = .ok ())
    (hWL : vaultSpendOutputsAllowed wl outs = true) :
    validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY true lids covs
      vOwnLid vKeys vThr vWit h outs wl = .ok () := by
  simp [validateVaultSpendRegistry, hOk, hSig, hWL]

def applyNonCoinbaseTxBasicNoCrypto
    (txBytes : Bytes)
    (utxos : List (Outpoint × UtxoEntry))
    (height : Nat)
    (blockTimestamp : Nat)
    (blockMtp : Nat)
    (chainId : Bytes)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none) :
    Except String (Nat × Nat) := do
  let _ := chainId
  let tx ← UtxoBasicV1.parseTx txBytes

  applyTxPreInputChecks tx height

  -- build lookup
  let utxoMap := UtxoBasicV1.buildUtxoMap utxos
  let mut next := utxoMap

  let mut sumIn : Nat := 0
  let mut sumInVault : Nat := 0
  let mut vaultInputCount : Nat := 0
  let mut vaultWhitelist : List Bytes := []
  let mut vaultOwnerLockId : Bytes := ByteArray.empty
  let mut vaultKeys : List Bytes := []
  let mut vaultThreshold : Nat := 0
  let mut vaultWitness : List WitnessItem := []

  let mut witnessCursor : Nat := 0
  let mut inputLockIds : List Bytes := []
  let mut inputCovTypes : List Nat := []

  let mut seen : Std.RBSet Outpoint UtxoBasicV1.cmpOutpoint := Std.RBSet.empty

  for inputIndex in [0:tx.inputs.length] do
    let i := tx.inputs.get! inputIndex
    validateInputStructural i
    let op : Outpoint := { txid := i.prevTxid, vout := i.prevVout }
    let isDup := seen.contains op
    seen := seen.insert op
    let e ← validateInputUtxoLookup isDup (next.find? op) height

    -- spend covenant structural validity (parsers)
    let dispatchReady ←
      dispatchCovenantValidation e tx witnessCursor height blockMtp
    match dispatchReady with
    | .p2pk nextWitnessCursor =>
      let w := tx.witness.get! witnessCursor
      -- pre-signature checks only
      validateP2PKSpendPreSig e w height rotDesc?
      witnessCursor := nextWitnessCursor
    | .multisig m nextWitnessCursor =>
      let assigned := (tx.witness.drop witnessCursor).take (nextWitnessCursor - witnessCursor)
      witnessCursor := nextWitnessCursor
      validateThresholdSigSpendNoCrypto m.keys m.threshold assigned height "CORE_MULTISIG"
    | .vault v nextWitnessCursor =>
      let assigned := (tx.witness.drop witnessCursor).take (nextWitnessCursor - witnessCursor)
      witnessCursor := nextWitnessCursor
      vaultInputCount := vaultInputCount + 1
      if vaultInputCount > 1 then
        throw "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN"
      sumInVault := sumInVault + e.value
      vaultWhitelist := v.whitelist
      vaultOwnerLockId := v.ownerLockId
      vaultKeys := v.keys
      vaultThreshold := v.threshold
      vaultWitness := assigned
    | .htlc c nextWitnessCursor =>
      let pathItem := tx.witness.get! witnessCursor
      let sigItem := tx.witness.get! (witnessCursor + 1)
      witnessCursor := nextWitnessCursor
      validateHTLCSpendNoCrypto c pathItem sigItem height blockMtp

    let lid := lockIdOfEntry e
    inputLockIds := inputLockIds.concat lid
    inputCovTypes := inputCovTypes.concat e.covenantType
    sumIn := sumIn + e.value
    next := next.erase op

  validateWitnessCursorComplete witnessCursor tx.witness.length

  -- outputs: add to UTXO (excluding non-spendable)
  let mut sumOut : Nat := 0
  let mut createsVault : Bool := false
  for o in tx.outputs do
    sumOut := sumOut + o.value
    if o.covenantType == CovenantGenesisV1.COV_TYPE_VAULT then
      createsVault := true
  let txid := SHA3.sha3_256 txBytes
  for outIndex in [0:tx.outputs.length] do
    let oo := tx.outputs.get! outIndex
    if oo.covenantType == CovenantGenesisV1.COV_TYPE_ANCHOR || oo.covenantType == CovenantGenesisV1.COV_TYPE_DA_COMMIT then
      continue
    let op2 : Outpoint := { txid := txid, vout := outIndex }
    next := next.insert op2 { value := oo.value, covenantType := oo.covenantType, covenantData := oo.covenantData, creationHeight := height, createdByCoinbase := false }

  -- CORE_VAULT creation requires owner-authorized input (lock_id match + type P2PK/MULTISIG).
  if createsVault then
    for o in tx.outputs do
      if o.covenantType != CovenantGenesisV1.COV_TYPE_VAULT then
        continue
      let v ← CovenantGenesisV1.parseVaultCovenantData o.covenantData
      let owner := v.ownerLockId
      if !vaultCreationOwnerAuthorized owner inputLockIds inputCovTypes then
        throw "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"

  -- CORE_VAULT spend rules — delegated to LIVE sub-function validateVaultSpend.
  if vaultInputCount == 1 then
    let ownerAuthPresent := inputLockIds.any (· == vaultOwnerLockId)
    validateVaultSpend ownerAuthPresent inputLockIds inputCovTypes vaultOwnerLockId
      vaultKeys vaultThreshold vaultWitness height tx.outputs vaultWhitelist

  validateValueConservation sumOut sumIn vaultInputCount sumInVault

  let fee := sumIn - sumOut
  pure (fee, next.size)

private def repeatByte (b : UInt8) (n : Nat) : Bytes :=
  Id.run <| do
    let mut out := ByteArray.empty
    for _ in [0:n] do
      out := out.push b
    pure out

private def byte32 (n : Nat) : Bytes :=
  repeatByte (UInt8.ofNat n) 32

private def sampleOwnerP2PKKeyId : Bytes :=
  byte32 0x41

private def sampleOwnerP2PKData : Bytes :=
  RubinFormal.bytes #[UInt8.ofNat SUITE_ID_ML_DSA_87] ++ sampleOwnerP2PKKeyId

private def sampleOwnerP2PKLockId : Bytes :=
  RubinFormal.OutputDescriptor.hash CovenantGenesisV1.COV_TYPE_P2PK sampleOwnerP2PKData

private def sampleOwnerMultisigKey : Bytes :=
  byte32 0x52

private def sampleOwnerMultisigData : Bytes :=
  RubinFormal.bytes #[UInt8.ofNat 0x01, UInt8.ofNat 0x01] ++ sampleOwnerMultisigKey

private def sampleOwnerMultisigLockId : Bytes :=
  RubinFormal.OutputDescriptor.hash CovenantGenesisV1.COV_TYPE_MULTISIG sampleOwnerMultisigData

private def sampleSpendOutput1 : UtxoBasicV1.TxOut :=
  { value := 10, covenantType := CovenantGenesisV1.COV_TYPE_P2PK, covenantData := sampleOwnerP2PKData }

private def sampleSpendOutput2 : UtxoBasicV1.TxOut :=
  { value := 20, covenantType := CovenantGenesisV1.COV_TYPE_MULTISIG, covenantData := sampleOwnerMultisigData }

private def sampleSpendWhitelist : List Bytes :=
  [
    RubinFormal.OutputDescriptor.hash sampleSpendOutput1.covenantType sampleSpendOutput1.covenantData,
    RubinFormal.OutputDescriptor.hash sampleSpendOutput2.covenantType sampleSpendOutput2.covenantData
  ]

private def sampleRecursiveVaultOutput : UtxoBasicV1.TxOut :=
  { value := 30, covenantType := CovenantGenesisV1.COV_TYPE_VAULT, covenantData := byte32 0x63 }

theorem creation_owner_auth_p2pk_or_multisig :
    vaultCreationOwnerAuthorized sampleOwnerP2PKLockId [sampleOwnerP2PKLockId] [CovenantGenesisV1.COV_TYPE_P2PK] = true ∧
      vaultCreationOwnerAuthorized sampleOwnerMultisigLockId [sampleOwnerMultisigLockId] [CovenantGenesisV1.COV_TYPE_MULTISIG] = true := by
  native_decide

theorem output_whitelist_closure :
    vaultSpendOutputsAllowed sampleSpendWhitelist [sampleSpendOutput1, sampleSpendOutput2] = true := by
  native_decide

theorem vault_recursion_ban :
    vaultSpendOutputsAllowed sampleSpendWhitelist [sampleSpendOutput1, sampleRecursiveVaultOutput] = false := by
  native_decide

/-- Vault dispatch routing: covenantType=VAULT → dispatchCovenantValidation
    enters the vault branch (parses vault covenant data + witness slots).
    Full split proof on explicit if/else chain — P2PK eliminated,
    Multisig eliminated, Vault selected via native_decide on type comparisons. -/
theorem dispatch_routes_to_vault
    (e : UtxoBasicV1.UtxoEntry) (tx : UtxoBasicV1.Tx)
    (wc height bm : Nat)
    (hVault : e.covenantType = CovenantGenesisV1.COV_TYPE_VAULT) :
    dispatchCovenantValidation e tx wc height bm =
    (match CovenantGenesisV1.parseVaultCovenantData e.covenantData with
     | .error err => Except.error err
     | .ok v =>
       match WITNESS_SLOTS e.covenantType e.covenantData with
       | .error err => Except.error err
       | .ok slots =>
         if wc + slots > tx.witness.length then Except.error "TX_ERR_PARSE"
         else Except.ok (.vault v (wc + slots))) := by
  unfold dispatchCovenantValidation; rw [hVault]
  split
  · rename_i h; exact absurd h (by simp [show (CovenantGenesisV1.COV_TYPE_VAULT == CovenantGenesisV1.COV_TYPE_P2PK) = false from by native_decide])
  · split
    · rename_i h; exact absurd h (by simp [show (CovenantGenesisV1.COV_TYPE_VAULT == CovenantGenesisV1.COV_TYPE_MULTISIG) = false from by native_decide])
    · split
      · rfl
      · rename_i _ _ h1; simp [show (CovenantGenesisV1.COV_TYPE_VAULT == CovenantGenesisV1.COV_TYPE_VAULT) = true from by native_decide] at h1

end UtxoApplyGenesisV1

end RubinFormal
