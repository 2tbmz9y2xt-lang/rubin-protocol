import RubinFormal.ConnectBlockStrong
import RubinFormal.CoinbaseBehavioral
import RubinFormal.TxContextBehavioral
import RubinFormal.SighashV1

/-!
# Full Block Connection with Coinbase + TxContext (§18/§19/§14)

Models the complete block connection path including:
1. Non-coinbase transaction validation (via connectBlockTxs)
2. Coinbase value bound + vault check
3. Coinbase UTXO creation
4. TxContext bundle construction (LIVE — wired, not parallel model)

Written with explicit match (no do) for formal proof access.
-/

namespace RubinFormal

open UtxoBasicV1 SubsidyV1

/-- Full block connection result with TxContext bundle. -/
structure ConnectBlockResult where
  utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint
  sumFees : Nat
  txContext : Option TxContextBundle

/-- Per-tx TxContext input data — resolved from UTXO lookup.
    In Go, this comes from resolved inputs (sumTxContextInputValues)
    and tx outputs (sumTxContextOutputValues). -/
structure TxContextInputData where
  inputValues : List Nat
  outputValues : List Nat
  activeExtIds : List Nat
  continuingData : List (Nat × TxContextContinuing)
  allowedSighashSet : UInt8
  sighashWitness : WitnessItem

/-- Derive the raw continuing-output counts from the same bundle data that
    will later be packed into the computed TxContext. This avoids validating
    detached metadata. -/
def continuingCountsFromData (continuingData : List (Nat × TxContextContinuing)) : List Nat :=
  continuingData.map fun pair => pair.2.outputs.length

/-- Extract the actual sighash byte from a witness item.
    Empty signatures fail before the policy gate runs. -/
def extractTxContextSighashType (w : WitnessItem) : Except String UInt8 :=
  if w.signature.size = 0 then
    .error "TX_ERR_SIG_INVALID"
  else
    .ok (w.signature.get! (w.signature.size - 1))

/-- Validate all raw continuing-output counts before packing the TxContext bundle.
    This wires the K-overflow reject helper into the live computed TxContext path. -/
def validateTxContextContinuingCounts : List Nat → Except String Unit
  | [] => .ok ()
  | count :: rest =>
      match validateContinuingOutputCount count with
      | .error err => .error err
      | .ok () => validateTxContextContinuingCounts rest

/-- Validate the txcontext sighash gate before building the bundle.
    Invalid base types map to `TX_ERR_SIGHASH_TYPE_INVALID`; disallowed but
    well-formed types map to `TX_ERR_SIG_ALG_INVALID`. -/
def validateTxContextSighashGate (allowedSet sighashType : UInt8) : Except String Unit :=
  if !SighashV1.hasValidBaseType sighashType then
    .error "TX_ERR_SIGHASH_TYPE_INVALID"
  else if SighashV1.checkSighashPolicy allowedSet sighashType then
    .ok ()
  else
    .error "TX_ERR_SIG_ALG_INVALID"

/-- Validate the txcontext sighash gate from the live witness bytes rather
    than a detached metadata byte. -/
def validateTxContextSighashWitness
    (allowedSet : UInt8) (w : WitnessItem) : Except String Unit :=
  match extractTxContextSighashType w with
  | .error err => .error err
  | .ok sighashType => validateTxContextSighashGate allowedSet sighashType

/-- Full block connection pipeline.
    TxContext parameters are threaded through for backward compatibility
    with existing proofs. See connectBlockFullComputed for the version
    that computes TxContext from tx data. -/
def connectBlockFull
    (nonCoinbaseTxs : List Bytes)
    (coinbaseOutputs : List CovenantGenesisV1.TxOut)
    (coinbaseTxid : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes) (subsidy : Nat)
    (activeExtIds : List Nat) (totalIn totalOut : Nat)
    (continuingData : List (Nat × TxContextContinuing))
    : Except String ConnectBlockResult :=
  match connectBlockTxs nonCoinbaseTxs utxoMap height blockTimestamp chainId with
  | .error e => .error e
  | .ok (sumFees, postTxUtxos) =>
    match validateCoinbaseValueBound coinbaseOutputs subsidy sumFees with
    | .error e => .error e
    | .ok () =>
      match validateCoinbaseApplyOutputs coinbaseOutputs with
      | .error e => .error e
      | .ok () =>
        .ok { utxoMap := addCoinbaseOutputs coinbaseOutputs coinbaseTxid height postTxUtxos
            , sumFees := sumFees
            , txContext := buildTxContext activeExtIds totalIn totalOut height continuingData }

/-- Full block connection with COMPUTED TxContext from tx data.
    This is the CORRECT version: TxContext is computed from resolved
    input/output values, not passed as free parameters.
    Uses buildTxContextLive which folds actual value lists and derives
    all pre-activation gate inputs from the same TxContext input bundle. -/
def connectBlockFullComputed
    (nonCoinbaseTxs : List Bytes)
    (coinbaseOutputs : List CovenantGenesisV1.TxOut)
    (coinbaseTxid : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes) (subsidy : Nat)
    (txCtxData : Option TxContextInputData)
    : Except String ConnectBlockResult :=
  match connectBlockTxs nonCoinbaseTxs utxoMap height blockTimestamp chainId with
  | .error e => .error e
  | .ok (sumFees, postTxUtxos) =>
    match validateCoinbaseValueBound coinbaseOutputs subsidy sumFees with
    | .error e => .error e
    | .ok () =>
      match validateCoinbaseApplyOutputs coinbaseOutputs with
      | .error e => .error e
      | .ok () =>
        match txCtxData with
        | none =>
            .ok { utxoMap := addCoinbaseOutputs coinbaseOutputs coinbaseTxid height postTxUtxos
                , sumFees := sumFees
                , txContext := none }
        | some d =>
            match validateTxContextContinuingCounts (continuingCountsFromData d.continuingData) with
            | .error e => .error e
            | .ok () =>
                match validateTxContextSighashWitness d.allowedSighashSet d.sighashWitness with
                | .error e => .error e
                | .ok () =>
                    .ok { utxoMap := addCoinbaseOutputs coinbaseOutputs coinbaseTxid height postTxUtxos
                        , sumFees := sumFees
                        , txContext := buildTxContextLive d.activeExtIds d.inputValues d.outputValues height d.continuingData }

/-- Equivalence under the computed-path gate assumptions:
    if the continuing-count and sighash validations succeed on the computed
    TxContext input bundle, then `connectBlockFullComputed` reduces to the
    aggregate compatibility wrapper `connectBlockFull` with computed sums.
    This bridges the two signatures; it is not an unconditional theorem that
    the wrapper itself enforces the extra gates. -/
theorem connectBlockFullComputed_eq_connectBlockFull
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat) (d : TxContextInputData) :
    validateTxContextContinuingCounts (continuingCountsFromData d.continuingData) = .ok () →
    validateTxContextSighashWitness d.allowedSighashSet d.sighashWitness = .ok () →
    connectBlockFullComputed nctxs couts ctxid utxos h bt cid sub (some d) =
    connectBlockFull nctxs couts ctxid utxos h bt cid sub
      d.activeExtIds (sumInputValues d.inputValues) (sumOutputValues d.outputValues) d.continuingData := by
  intro hCounts hSighash
  simp [connectBlockFullComputed, connectBlockFull, buildTxContextLive, buildTxContext, sumInputValues, sumOutputValues, hCounts, hSighash]

/-- connectBlockFullComputed with None = connectBlockFull with empty ext_ids. -/
theorem connectBlockFullComputed_none_eq
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat) :
    connectBlockFullComputed nctxs couts ctxid utxos h bt cid sub none =
    connectBlockFull nctxs couts ctxid utxos h bt cid sub [] 0 0 [] := by
  simp [connectBlockFullComputed, connectBlockFull, buildTxContextLive, buildTxContext]

/-- Computed TxContext has correct base values from tx data. -/
theorem connectBlockFullComputed_txcontext_correct
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat) (d : TxContextInputData)
    (hIds : d.activeExtIds.length > 0)
    (result : ConnectBlockResult)
    (hOk : connectBlockFullComputed nctxs couts ctxid utxos h bt cid sub (some d) = .ok result) :
    ∃ bundle, result.txContext = some bundle ∧
      bundle.base.totalIn = sumInputValues d.inputValues ∧
      bundle.base.totalOut = sumOutputValues d.outputValues ∧
      bundle.base.height = h := by
  simp only [connectBlockFullComputed] at hOk
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hT] at hOk
  | .ok (sf, ptx) =>
    simp [hT] at hOk
    match hB : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hB] at hOk
    | .ok () =>
      simp [hB] at hOk
      match hV : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hV] at hOk
      | .ok () =>
        simp [hV] at hOk
        match hCounts : validateTxContextContinuingCounts (continuingCountsFromData d.continuingData) with
        | .error _ => simp [hCounts] at hOk
        | .ok () =>
          simp [hCounts] at hOk
          match hSighash : validateTxContextSighashWitness d.allowedSighashSet d.sighashWitness with
          | .error _ => simp [hSighash] at hOk
          | .ok () =>
            simp [hSighash] at hOk
            cases hOk
            simp [buildTxContextLive, buildTxContext, sumInputValues, sumOutputValues]
            split
            · rename_i heq; omega
            · exact ⟨_, rfl, rfl, rfl, rfl⟩

/-- Computed TxContext preserves the live continuing bundle data from the same
    validated txcontext input surface. -/
theorem connectBlockFullComputed_txcontext_continuing_data
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat) (d : TxContextInputData)
    (hIds : d.activeExtIds.length > 0)
    (result : ConnectBlockResult) (bundle : TxContextBundle)
    (hOk : connectBlockFullComputed nctxs couts ctxid utxos h bt cid sub (some d) = .ok result)
    (hBundle : result.txContext = some bundle) :
    bundle.continuingByExt = d.continuingData := by
  simp only [connectBlockFullComputed] at hOk
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hT] at hOk
  | .ok (sf, ptx) =>
    simp [hT] at hOk
    match hB : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hB] at hOk
    | .ok () =>
      simp [hB] at hOk
      match hV : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hV] at hOk
      | .ok () =>
        simp [hV] at hOk
        match hCounts : validateTxContextContinuingCounts (continuingCountsFromData d.continuingData) with
        | .error _ => simp [hCounts] at hOk
        | .ok () =>
          simp [hCounts] at hOk
          match hSighash : validateTxContextSighashWitness d.allowedSighashSet d.sighashWitness with
          | .error _ => simp [hSighash] at hOk
          | .ok () =>
            simp [hSighash] at hOk
            cases hOk
            have hBuild :
                buildTxContext d.activeExtIds
                  (sumInputValues d.inputValues)
                  (sumOutputValues d.outputValues)
                  h d.continuingData = some bundle := by
              simpa [buildTxContextLive, buildTxContext, sumInputValues, sumOutputValues] using hBundle
            exact buildTxContext_continuing_data
              d.activeExtIds hIds _ _ _ d.continuingData bundle hBuild

/-- Success on the computed parallel block-connection path implies that the
    live TxContext input bundle passed both computed-path gates. This exposes
    the exact shared validated surface on which
    `connectBlockFullComputed_eq_connectBlockFull` is an equality theorem,
    rather than leaving those assumptions as free-floating registry prose. -/
theorem connectBlockFullComputed_ok_implies_txctx_gates
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat) (d : TxContextInputData)
    (result : ConnectBlockResult)
    (hOk : connectBlockFullComputed nctxs couts ctxid utxos h bt cid sub (some d) = .ok result) :
    validateTxContextContinuingCounts (continuingCountsFromData d.continuingData) = .ok () ∧
    validateTxContextSighashWitness d.allowedSighashSet d.sighashWitness = .ok () := by
  simp only [connectBlockFullComputed] at hOk
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hT] at hOk
  | .ok (sf, ptx) =>
    simp [hT] at hOk
    match hB : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hB] at hOk
    | .ok () =>
      simp [hB] at hOk
      match hV : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hV] at hOk
      | .ok () =>
        simp [hV] at hOk
        match hCounts : validateTxContextContinuingCounts (continuingCountsFromData d.continuingData) with
        | .error _ => simp [hCounts] at hOk
        | .ok () =>
          simp [hCounts] at hOk
          match hSighash : validateTxContextSighashWitness d.allowedSighashSet d.sighashWitness with
          | .error _ => simp [hSighash] at hOk
          | .ok () =>
            simp [hSighash] at hOk
            constructor <;> rfl

/-! ## Helper: extract connectBlockTxs success -/

private theorem connectBlockFull_txs_ok
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result) :
    ∃ postTxUtxos,
      connectBlockTxs nctxs utxos h bt cid = .ok (result.sumFees, postTxUtxos) := by
  simp only [connectBlockFull] at hOk
  match hTxs : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hTxs] at hOk
  | .ok (sf, ptx) =>
    simp [hTxs] at hOk
    match hBound : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hBound] at hOk
    | .ok () =>
      simp [hBound] at hOk
      match hVault : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hVault] at hOk
      | .ok () =>
        simp [hVault] at hOk; obtain ⟨_, rfl, _⟩ := hOk; exact ⟨ptx, rfl⟩

/-! ## Non-coinbase behavioral proofs -/

/-- Full connection success → non-coinbase conservation + no-double-spend. -/
theorem connectBlockFull_preserves_noncoinbase_invariants
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result) :
    utxo_conserved nctxs utxos h bt cid ∧
    no_double_spend nctxs utxos h bt cid := by
  obtain ⟨ptx, hTxs⟩ := connectBlockFull_txs_ok _ _ _ _ _ _ _ _ _ _ _ _ _ hOk
  exact ⟨utxo_conservation_theorem _ _ _ _ _ _ _ hTxs,
         no_double_spend_theorem _ _ _ _ _ _ _ hTxs⟩

/-- Full connection success → coinbase value ≤ subsidy + fees. -/
theorem connectBlockFull_coinbase_bound
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result) :
    ¬(sumCoinbaseOutputs couts > sub + result.sumFees) := by
  simp only [connectBlockFull] at hOk
  match hTxs : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hTxs] at hOk
  | .ok (sf, ptx) =>
    simp [hTxs] at hOk
    match hBound : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hBound] at hOk
    | .ok () =>
      simp [hBound] at hOk
      match hVault : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hVault] at hOk
      | .ok () =>
        simp [hVault] at hOk; obtain ⟨_, rfl, _⟩ := hOk
        simp only [validateCoinbaseValueBound] at hBound
        by_cases hGt : sumCoinbaseOutputs couts > sub + sf
        · simp [hGt] at hBound
        · exact hGt

/-- Full connection success → no CORE_VAULT in coinbase. -/
theorem connectBlockFull_no_vault
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result) :
    couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false := by
  simp only [connectBlockFull] at hOk
  match hTxs : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hTxs] at hOk
  | .ok (sf, ptx) =>
    simp [hTxs] at hOk
    match hBound : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hBound] at hOk
    | .ok () =>
      simp [hBound] at hOk
      match hVault : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hVault] at hOk
      | .ok () =>
        by_cases hAny : couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = true
        · have : validateCoinbaseApplyOutputs couts = .error "BLOCK_ERR_COINBASE_INVALID" :=
            coinbase_no_vault_rejects couts hAny
          rw [this] at hVault; simp at hVault
        · exact Bool.eq_false_iff.mpr (fun hh => hAny hh)

/-! ## Error branch proofs -/

/-- Non-coinbase tx failure → full connect rejected with same error. -/
theorem connectBlockFull_rejects_bad_txs
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (err : String)
    (hFail : connectBlockTxs nctxs utxos h bt cid = .error err) :
    connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .error err := by
  simp [connectBlockFull, hFail]

/-- Coinbase exceeds subsidy+fees → full connect rejected. -/
theorem connectBlockFull_rejects_oversized_coinbase
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (sumFees : Nat) (postTxUtxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hTxs : connectBlockTxs nctxs utxos h bt cid = .ok (sumFees, postTxUtxos))
    (hOver : sumCoinbaseOutputs couts > sub + sumFees) :
    connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd =
    .error "BLOCK_ERR_SUBSIDY_EXCEEDED" := by
  simp [connectBlockFull, hTxs, validateCoinbaseValueBound, hOver]

/-- CORE_VAULT in coinbase → full connect rejected. -/
theorem connectBlockFull_rejects_vault_coinbase
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (sumFees : Nat) (postTxUtxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hTxs : connectBlockTxs nctxs utxos h bt cid = .ok (sumFees, postTxUtxos))
    (hBound : ¬(sumCoinbaseOutputs couts > sub + sumFees))
    (hVault : couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = true) :
    connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd =
    .error "BLOCK_ERR_COINBASE_INVALID" := by
  simp [connectBlockFull, hTxs, validateCoinbaseValueBound, hBound,
        validateCoinbaseApplyOutputs, hVault]

/-! ## Structural ordering -/

/-- Coinbase processed strictly AFTER all non-coinbase txs. -/
theorem coinbase_processed_after_noncoinbase
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result) :
    ∃ sf ptx, connectBlockTxs nctxs utxos h bt cid = .ok (sf, ptx) := by
  simp only [connectBlockFull] at hOk
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hT] at hOk
  | .ok (sf, ptx) => exact ⟨sf, ptx, rfl⟩

/-! ## Error taxonomy (replaces former axiom) -/

/-- Structural correspondence: connectBlockFull returns ONLY canonical
    error codes. Machine-checked exhaustive proof, zero axioms. -/
theorem connectBlockFull_error_taxonomy
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (err : String)
    (hFail : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .error err) :
    err = "BLOCK_ERR_SUBSIDY_EXCEEDED" ∨
    err = "BLOCK_ERR_COINBASE_INVALID" ∨
    (∃ txErr, connectBlockTxs nctxs utxos h bt cid = .error txErr ∧ err = txErr) := by
  simp only [connectBlockFull] at hFail
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error e =>
    simp [hT] at hFail; exact Or.inr (Or.inr ⟨e, rfl, hFail.symm⟩)
  | .ok (sf, ptx) =>
    simp [hT] at hFail
    by_cases hOver : sumCoinbaseOutputs couts > sub + sf
    · have hB : validateCoinbaseValueBound couts sub sf = .error "BLOCK_ERR_SUBSIDY_EXCEEDED" :=
        coinbase_value_bound_rejects couts sub sf hOver
      simp [hB] at hFail; exact Or.inl hFail.symm
    · have hB : validateCoinbaseValueBound couts sub sf = .ok () :=
        coinbase_value_bound_accepts couts sub sf hOver
      simp [hB] at hFail
      by_cases hVault : couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = true
      · have hV : validateCoinbaseApplyOutputs couts = .error "BLOCK_ERR_COINBASE_INVALID" :=
          coinbase_no_vault_rejects couts hVault
        simp [hV] at hFail; exact Or.inr (Or.inl hFail.symm)
      · have hNotV := Bool.eq_false_iff.mpr (fun hh => hVault hh)
        have hV : validateCoinbaseApplyOutputs couts = .ok () :=
          coinbase_no_vault_accepts couts hNotV
        simp [hV] at hFail

/-! ## TxContext wiring proofs (LIVE — not parallel model) -/

/-- If block connects with active ext_ids, TxContext bundle is produced. -/
theorem connectBlockFull_produces_txcontext
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (hIds : ids.length > 0)
    (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result) :
    result.txContext.isSome = true := by
  simp only [connectBlockFull] at hOk
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hT] at hOk
  | .ok (sf, ptx) =>
    simp [hT] at hOk
    match hB : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hB] at hOk
    | .ok () =>
      simp [hB] at hOk
      match hV : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hV] at hOk
      | .ok () =>
        simp [hV] at hOk; obtain ⟨_, _, rfl⟩ := hOk
        exact buildTxContext_some ids hIds tin tout h cd

/-- If block connects with no active ext_ids, no TxContext bundle. -/
theorem connectBlockFull_no_txcontext_when_empty
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub [] tin tout cd = .ok result) :
    result.txContext = none := by
  simp only [connectBlockFull] at hOk
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hT] at hOk
  | .ok (sf, ptx) =>
    simp [hT] at hOk
    match hB : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hB] at hOk
    | .ok () =>
      simp [hB] at hOk
      match hV : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hV] at hOk
      | .ok () =>
        simp [hV] at hOk; obtain ⟨_, _, rfl⟩ := hOk
        rfl

/-- TxContext bundle in result has the live deterministic ext_id order. -/
theorem connectBlockFull_txcontext_ext_ids
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (hIds : ids.length > 0)
    (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult) (bundle : TxContextBundle)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result)
    (hBundle : result.txContext = some bundle) :
    bundle.continuingExtIds = sortExtIds ids := by
  simp only [connectBlockFull] at hOk
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hT] at hOk
  | .ok (sf, ptx) =>
    simp [hT] at hOk
    match hB : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hB] at hOk
    | .ok () =>
      simp [hB] at hOk
      match hV : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hV] at hOk
      | .ok () =>
        simp [hV] at hOk; obtain ⟨_, _, rfl⟩ := hOk
        exact buildTxContext_ext_ids ids hIds tin tout h cd bundle hBundle

/-- TxContext bundle has correct base values (totalIn, totalOut, height). -/
theorem connectBlockFull_txcontext_base_values
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (hIds : ids.length > 0)
    (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult) (bundle : TxContextBundle)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result)
    (hBundle : result.txContext = some bundle) :
    bundle.base.totalIn = tin ∧ bundle.base.totalOut = tout ∧ bundle.base.height = h := by
  simp only [connectBlockFull] at hOk
  match hT : connectBlockTxs nctxs utxos h bt cid with
  | .error _ => simp [hT] at hOk
  | .ok (sf, ptx) =>
    simp [hT] at hOk
    match hB : validateCoinbaseValueBound couts sub sf with
    | .error _ => simp [hB] at hOk
    | .ok () =>
      simp [hB] at hOk
      match hV : validateCoinbaseApplyOutputs couts with
      | .error _ => simp [hV] at hOk
      | .ok () =>
        simp [hV] at hOk; obtain ⟨_, _, rfl⟩ := hOk
        exact buildTxContext_base_values ids hIds tin tout h cd bundle hBundle

/-! ## End-to-end scenario -/

/-- Valid block end-to-end: ALL invariants hold simultaneously.
    Conservation + no-double-spend + coinbase bound + no-vault + TxContext presence. -/
theorem valid_block_end_to_end
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (ids : List Nat) (hIds : ids.length > 0)
    (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub ids tin tout cd = .ok result) :
    utxo_conserved nctxs utxos h bt cid ∧
    no_double_spend nctxs utxos h bt cid ∧
    ¬(sumCoinbaseOutputs couts > sub + result.sumFees) ∧
    couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false ∧
    result.txContext.isSome = true :=
  ⟨(connectBlockFull_preserves_noncoinbase_invariants _ _ _ _ _ _ _ _ _ _ _ _ _ hOk).1,
   (connectBlockFull_preserves_noncoinbase_invariants _ _ _ _ _ _ _ _ _ _ _ _ _ hOk).2,
   connectBlockFull_coinbase_bound _ _ _ _ _ _ _ _ _ _ _ _ _ hOk,
   connectBlockFull_no_vault _ _ _ _ _ _ _ _ _ _ _ _ _ hOk,
   connectBlockFull_produces_txcontext _ _ _ _ _ _ _ _ _ hIds _ _ _ _ hOk⟩

/-! ## End-to-end without ext_ids (Gap 5) -/

/-- Valid block end-to-end WITHOUT active ext_ids.
    4-way invariant + txContext = none. -/
theorem valid_block_end_to_end_no_extids
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (tin tout : Nat) (cd : List (Nat × TxContextContinuing))
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub [] tin tout cd = .ok result) :
    utxo_conserved nctxs utxos h bt cid ∧
    no_double_spend nctxs utxos h bt cid ∧
    ¬(sumCoinbaseOutputs couts > sub + result.sumFees) ∧
    couts.any (fun o => o.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false ∧
    result.txContext = none :=
  ⟨(connectBlockFull_preserves_noncoinbase_invariants _ _ _ _ _ _ _ _ _ _ _ _ _ hOk).1,
   (connectBlockFull_preserves_noncoinbase_invariants _ _ _ _ _ _ _ _ _ _ _ _ _ hOk).2,
   connectBlockFull_coinbase_bound _ _ _ _ _ _ _ _ _ _ _ _ _ hOk,
   connectBlockFull_no_vault _ _ _ _ _ _ _ _ _ _ _ _ _ hOk,
   connectBlockFull_no_txcontext_when_empty _ _ _ _ _ _ _ _ _ _ _ _ hOk⟩

/-! ## Per-tx TxContext with COMPUTED values (not alias)

In Go, BuildTxContext is called PER-TX with resolved input/output values.
buildPerTxContextFromData takes raw value lists and COMPUTES sums. -/

/-- Per-tx TxContext from RESOLVED inputs and outputs.
    NOT an alias — takes raw value lists and computes totalIn/totalOut via fold.
    Models Go BuildTxContext per-tx call in connect_block_parallel.go. -/
def buildPerTxContextFromData
    (txActiveExtIds : List Nat)
    (txInputValues txOutputValues : List Nat)
    (height : Nat)
    (txContinuingData : List (Nat × TxContextContinuing))
    : Option TxContextBundle :=
  buildTxContextLive txActiveExtIds txInputValues txOutputValues height txContinuingData

/-- Per-tx base values are COMPUTED from actual tx input/output values. -/
theorem perTx_base_values_computed
    (ids : List Nat) (hIds : ids.length > 0)
    (inVals outVals : List Nat) (height : Nat)
    (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildPerTxContextFromData ids inVals outVals height cd = some bundle) :
    bundle.base.totalIn = inVals.foldl (· + ·) 0 ∧
    bundle.base.totalOut = outVals.foldl (· + ·) 0 ∧
    bundle.base.height = height := by
  simp [buildPerTxContextFromData, buildTxContextLive, buildTxContext] at hEq
  split at hEq
  · rename_i heq; omega
  · cases hEq; exact ⟨rfl, rfl, rfl⟩

/-- Per-tx ext_ids are normalized into the live deterministic order. -/
theorem perTx_ext_ids_preserved
    (ids : List Nat) (hIds : ids.length > 0)
    (inVals outVals : List Nat) (height : Nat)
    (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildPerTxContextFromData ids inVals outVals height cd = some bundle) :
    bundle.continuingExtIds = sortExtIds ids := by
  simp [buildPerTxContextFromData, buildTxContextLive, buildTxContext] at hEq
  split at hEq
  · rename_i heq; omega
  · cases hEq; rfl

/-- Per-tx value conservation: inputs ≥ outputs → totalIn ≥ totalOut. -/
theorem perTx_value_conservation
    (ids : List Nat) (hIds : ids.length > 0)
    (inVals outVals : List Nat) (height : Nat)
    (cd : List (Nat × TxContextContinuing))
    (bundle : TxContextBundle)
    (hEq : buildPerTxContextFromData ids inVals outVals height cd = some bundle)
    (hFee : inVals.foldl (· + ·) 0 ≥ outVals.foldl (· + ·) 0) :
    bundle.base.totalIn ≥ bundle.base.totalOut := by
  have ⟨hIn, hOut, _⟩ := perTx_base_values_computed ids hIds inVals outVals height cd bundle hEq
  omega

/-! ## Vault error propagation (R14 integration)

Vault rules are enforced per-tx inside connectBlockTxs → applyNonCoinbaseTxBasicState →
applyNonCoinbaseTxBasicNoCrypto → validateVaultSpend (LIVE, line 472).
All vault errors propagate to block level via connectBlockFull_rejects_bad_txs
(generic error propagation). No separate vault-specific wrappers needed. -/

/-! ## Guard lemma

connectBlockFull has exactly 4 match arms + TxContext construction:
1. connectBlockTxs error → propagate
2. validateCoinbaseValueBound error → BLOCK_ERR_SUBSIDY_EXCEEDED
3. validateCoinbaseApplyOutputs error → BLOCK_ERR_COINBASE_INVALID
4. ok → construct result with coinbase UTXOs + TxContext bundle

Adding a 5th validation step requires updating every theorem above.
Lean's exhaustiveness checker enforces this: missing arm → compile error. -/

end RubinFormal
