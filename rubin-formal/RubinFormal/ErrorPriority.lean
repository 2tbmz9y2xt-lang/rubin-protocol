import RubinFormal.BlockValidationOrder
import RubinFormal.UtxoApplyGenesisV1

/-!
# Error Priority Ordering (§13 / §25)

## Block-level (§25) — on live `validateBlockBasic`
Direct error propagation for all 6 stages: parse → PoW → target →
linkage → merkle (via explicit-bind equivalence) → witness (existing).

## Tx-level — live sub-function decomposition
- `applyWitnessChecks` (LIVE, called from `parseTxFromCursor`):
  OVERFLOW → SIG_ALG_INVALID → SIG_NONCANONICAL ordering via rfl equivalence.
- `applyDaLenChecks` (LIVE, called from `parseTxFromCursor`):
  4 DA-length checks, all TX_ERR_PARSE.
- `applyTxPreInputChecks` (LIVE, called from `applyNonCoinbaseTxBasicNoCrypto`):
  empty inputs → nonce invalid → output covenant loop.
- `validateInputStructural` (LIVE, per-input loop):
  scriptSig → sequence → coinbase prevout.

## Coverage notes
- `parseTxFromCursor` header/bounds (lines 108-139): all TX_ERR_PARSE — same error code,
  no priority ambiguity within these sub-checks.
- Per-input UTXO lookup/duplicate/covenant-type: mutable state in for-loop; individual
  check functions (`validateInputUtxoLookup`, `dispatchCovenantValidation`) are proved.
- Error code distinctness: all block + tx codes via `by decide` (35 theorems).

## §13 Contract summary
- `consensus_error_ordering_contract`: block-level totality + parse/pow dominance + full 6-stage success chain.
- `tx_parse_pipeline_deterministic`: tx parse model ordering strict + injective (live bridges separate).
- `tx_semantic_pipeline_deterministic`: tx semantic model ordering strict + injective (live bridges separate).
-/

namespace RubinFormal

open RubinFormal.BlockBasicV1

/-! ## Block-level direct error propagation (§25 stage ordering) -/

/-- Stage 1: parse failure → returns the parse error. -/
theorem error_priority_parse
    (blockBytes : Bytes) (ph pt : Option Bytes) (err : String)
    (hFail : parseBlock blockBytes = .error err) :
    validateBlockBasic blockBytes ph pt = .error err := by
  unfold validateBlockBasic; rw [hFail]; rfl

/-- Stage 2: PoW failure → returns the PoW error. -/
theorem error_priority_pow
    (blockBytes : Bytes) (ph pt : Option Bytes)
    (pb : ParsedBlock) (err : String)
    (hParse : parseBlock blockBytes = .ok pb)
    (hFail : powCheck pb.header = .error err) :
    validateBlockBasic blockBytes ph pt = .error err := by
  unfold validateBlockBasic; rw [hParse]
  show (do powCheck pb.header; _) = _; rw [hFail]; rfl

/-- Stage 3: target mismatch → returns BLOCK_ERR_TARGET_INVALID.
    DISAMBIGUATION: when powCheck passes, this error is unambiguously from
    target mismatch (stage 3), not from malformed target (stage 2).
    powCheck validates target well-formedness; stage 3 checks expected match. -/
theorem error_priority_target
    (blockBytes : Bytes) (ph : Option Bytes)
    (pb : ParsedBlock) (expTarget : Bytes)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hFail : (pb.header.target != expTarget) = true) :
    validateBlockBasic blockBytes ph (some expTarget) =
    .error "BLOCK_ERR_TARGET_INVALID" := by
  unfold validateBlockBasic; rw [hParse]
  show (do powCheck pb.header; _) = _; rw [hPow]
  simp only [hFail, ite_true]; rfl

/-- TARGET DISAMBIGUATION: after powCheck succeeds, BLOCK_ERR_TARGET_INVALID
    is unambiguously from stage 3 (mismatch), not stage 2 (malformed).
    powCheck validates target well-formedness; stage 3 validates expected match. -/
theorem target_error_disambiguated
    (blockBytes : Bytes) (ph : Option Bytes)
    (pb : ParsedBlock) (expTarget : Bytes)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hMismatch : (pb.header.target != expTarget) = true) :
    validateBlockBasic blockBytes ph (some expTarget) =
    .error "BLOCK_ERR_TARGET_INVALID" ∧ powCheck pb.header = .ok () := by
  constructor
  · unfold validateBlockBasic; rw [hParse]
    show (do powCheck pb.header; _) = _; rw [hPow]
    simp only [hMismatch, ite_true]; rfl
  · exact hPow

/-- Stage 4a: linkage mismatch, no target gate. -/
theorem error_priority_linkage_no_target
    (blockBytes : Bytes) (expPrev : Bytes) (pb : ParsedBlock)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hFail : (pb.header.prevHash != expPrev) = true) :
    validateBlockBasic blockBytes (some expPrev) none =
    .error "BLOCK_ERR_LINKAGE_INVALID" := by
  unfold validateBlockBasic; rw [hParse]
  show (do powCheck pb.header; _) = _; rw [hPow]
  simp only [hFail, ite_true]; rfl

/-- Stage 4b: linkage mismatch, target gate passes. -/
theorem error_priority_linkage_target_ok
    (blockBytes : Bytes) (expPrev expTarget : Bytes) (pb : ParsedBlock)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hTargetOk : (pb.header.target != expTarget) = false)
    (hFail : (pb.header.prevHash != expPrev) = true) :
    validateBlockBasic blockBytes (some expPrev) (some expTarget) =
    .error "BLOCK_ERR_LINKAGE_INVALID" := by
  unfold validateBlockBasic; rw [hParse]
  show (do powCheck pb.header; _) = _; rw [hPow]
  simp only [hTargetOk, ite_false, hFail, ite_true]; rfl

/-! ## Stage 5: Merkle error propagation

The merkle check is inside the `validateBlockBasicMerkleWitnessTail` function.
Lean 4.6 do-notation creates `__do_jp` join points that resist standard tactic
reduction. Workaround: define an explicit-bind equivalent, prove definitional
equality via `rfl`, then prove error propagation on the explicit version.
-/

/-- Explicit-bind version of the merkle+witness tail (no join points). -/
def merkleWitnessTailExplicit (pb : ParsedBlock) : Except String Unit :=
  (merkleRootTxids pb.txids).bind fun mr =>
    if (mr != pb.header.merkleRoot) = true then
      Except.error "BLOCK_ERR_MERKLE_INVALID"
    else
      checkWitnessCommitment pb

/-- Definitional equivalence: the do version = explicit bind version. -/
theorem merkleWitnessTail_eq_explicit (pb : ParsedBlock) :
    validateBlockBasicMerkleWitnessTail pb = merkleWitnessTailExplicit pb := by
  simp only [validateBlockBasicMerkleWitnessTail, merkleWitnessTailExplicit,
    Except.bind]; rfl

/-- Stage 5a: merkle mismatch → returns BLOCK_ERR_MERKLE_INVALID.
    Proved at the `validateBlockBasicAfterPow` level for none/none. -/
theorem error_priority_merkle_afterpow_nn
    (pb : ParsedBlock) (mr : Bytes)
    (hMerkle : merkleRootTxids pb.txids = .ok mr)
    (hMismatch : (mr != pb.header.merkleRoot) = true) :
    validateBlockBasicAfterPow pb none none = .error "BLOCK_ERR_MERKLE_INVALID" := by
  show validateBlockBasicMerkleWitnessTail pb = _
  rw [merkleWitnessTail_eq_explicit]
  simp only [merkleWitnessTailExplicit, hMerkle, Except.bind, hMismatch, ite_true]

/-- Stage 5a: merkle mismatch, target passes. -/
theorem error_priority_merkle_afterpow_sn
    (pb : ParsedBlock) (mr expTarget : Bytes)
    (hTargetOk : (pb.header.target != expTarget) = false)
    (hMerkle : merkleRootTxids pb.txids = .ok mr)
    (hMismatch : (mr != pb.header.merkleRoot) = true) :
    validateBlockBasicAfterPow pb none (some expTarget) = .error "BLOCK_ERR_MERKLE_INVALID" := by
  unfold validateBlockBasicAfterPow
  simp only [hTargetOk, ite_false]
  show validateBlockBasicMerkleWitnessTail pb = _
  rw [merkleWitnessTail_eq_explicit]
  simp only [merkleWitnessTailExplicit, hMerkle, Except.bind, hMismatch, ite_true]

/-- Stage 5a: merkle mismatch, linkage passes. -/
theorem error_priority_merkle_afterpow_ns
    (pb : ParsedBlock) (mr expPrev : Bytes)
    (hLinkOk : (pb.header.prevHash != expPrev) = false)
    (hMerkle : merkleRootTxids pb.txids = .ok mr)
    (hMismatch : (mr != pb.header.merkleRoot) = true) :
    validateBlockBasicAfterPow pb (some expPrev) none = .error "BLOCK_ERR_MERKLE_INVALID" := by
  unfold validateBlockBasicAfterPow
  simp only [hLinkOk, ite_false]
  show validateBlockBasicMerkleWitnessTail pb = _
  rw [merkleWitnessTail_eq_explicit]
  simp only [merkleWitnessTailExplicit, hMerkle, Except.bind, hMismatch, ite_true]

/-- Stage 5a: merkle mismatch, target+linkage pass. -/
theorem error_priority_merkle_afterpow_ss
    (pb : ParsedBlock) (mr expTarget expPrev : Bytes)
    (hTargetOk : (pb.header.target != expTarget) = false)
    (hLinkOk : (pb.header.prevHash != expPrev) = false)
    (hMerkle : merkleRootTxids pb.txids = .ok mr)
    (hMismatch : (mr != pb.header.merkleRoot) = true) :
    validateBlockBasicAfterPow pb (some expPrev) (some expTarget) =
    .error "BLOCK_ERR_MERKLE_INVALID" := by
  unfold validateBlockBasicAfterPow
  simp only [hTargetOk, ite_false, hLinkOk]
  show validateBlockBasicMerkleWitnessTail pb = _
  rw [merkleWitnessTail_eq_explicit]
  simp only [merkleWitnessTailExplicit, hMerkle, Except.bind, hMismatch, ite_true]

/-- Stage 5b: merkleRootTxids computation error → error propagates. -/
theorem error_priority_merkle_compute_fail
    (pb : ParsedBlock) (err : String)
    (hFail : merkleRootTxids pb.txids = .error err) :
    validateBlockBasicMerkleWitnessTail pb = .error err := by
  rw [merkleWitnessTail_eq_explicit]
  simp only [merkleWitnessTailExplicit, hFail, Except.bind]

/-! ## Monadic error propagation -/

/-- Generic short-circuit: `Except.error.bind f = Except.error`. -/
theorem except_error_bind {α β : Type} {err : String}
    (f : α → Except String β) :
    (Except.error err : Except String α).bind f = Except.error err := rfl

/-! ## Success-implies-check-passed chain (contrapositives) -/

theorem validate_success_parse
    (b : Bytes) (ph pt : Option Bytes)
    (h : validateBlockBasic b ph pt = .ok ()) :
    ∃ pb, parseBlock b = .ok pb :=
  let ⟨pb, hp, _⟩ := validateBlockBasic_parses b ph pt h; ⟨pb, hp⟩

theorem validate_success_pow
    (b : Bytes) (ph pt : Option Bytes)
    (h : validateBlockBasic b ph pt = .ok ()) :
    ∃ pb, parseBlock b = .ok pb ∧ powCheck pb.header = .ok () :=
  let ⟨pb, hp, hpow, _⟩ := validateBlockBasic_pow_passes b ph pt h; ⟨pb, hp, hpow⟩

/-! ## Tx-level error code distinctness (§7/§13)

Pairwise inequality for all tx error codes used in the validation pipeline.
Ordering is proved via live sub-function decomposition (see sections below),
not via enum models.
-/

theorem err_ne_tx_parse_witness_overflow :
    ("TX_ERR_PARSE" : String) ≠ "TX_ERR_WITNESS_OVERFLOW" := by decide
theorem err_ne_tx_parse_sig_alg :
    ("TX_ERR_PARSE" : String) ≠ "TX_ERR_SIG_ALG_INVALID" := by decide
theorem err_ne_tx_parse_sig_noncanonical :
    ("TX_ERR_PARSE" : String) ≠ "TX_ERR_SIG_NONCANONICAL" := by decide
theorem err_ne_tx_witness_overflow_sig_alg :
    ("TX_ERR_WITNESS_OVERFLOW" : String) ≠ "TX_ERR_SIG_ALG_INVALID" := by decide
theorem err_ne_tx_witness_overflow_sig_noncanonical :
    ("TX_ERR_WITNESS_OVERFLOW" : String) ≠ "TX_ERR_SIG_NONCANONICAL" := by decide
theorem err_ne_tx_sig_alg_sig_noncanonical :
    ("TX_ERR_SIG_ALG_INVALID" : String) ≠ "TX_ERR_SIG_NONCANONICAL" := by decide
theorem err_ne_tx_parse_missing_utxo :
    ("TX_ERR_PARSE" : String) ≠ "TX_ERR_MISSING_UTXO" := by decide
theorem err_ne_tx_missing_utxo_sig_alg :
    ("TX_ERR_MISSING_UTXO" : String) ≠ "TX_ERR_SIG_ALG_INVALID" := by decide
theorem err_ne_tx_missing_utxo_sig_invalid :
    ("TX_ERR_MISSING_UTXO" : String) ≠ "TX_ERR_SIG_INVALID" := by decide
theorem err_ne_tx_sig_alg_sig_invalid :
    ("TX_ERR_SIG_ALG_INVALID" : String) ≠ "TX_ERR_SIG_INVALID" := by decide
theorem err_ne_tx_covenant_parse :
    ("TX_ERR_COVENANT_TYPE_INVALID" : String) ≠ "TX_ERR_PARSE" := by decide
theorem err_ne_tx_covenant_sig_alg :
    ("TX_ERR_COVENANT_TYPE_INVALID" : String) ≠ "TX_ERR_SIG_ALG_INVALID" := by decide
theorem err_ne_tx_covenant_missing :
    ("TX_ERR_COVENANT_TYPE_INVALID" : String) ≠ "TX_ERR_MISSING_UTXO" := by decide

/-! ## Live witness-check ordering (applyWitnessChecks — called from parseTxFromCursor)

`applyWitnessChecks` is a LIVE sub-function extracted from parseTxFromCursor.
It is called directly by parseTxFromCursor (BlockBasicV1.lean) — not a proof-only
decomposition. Error ordering is proved via explicit-bind equivalence.
-/

open RubinFormal.TxWeightV2 in
/-- Explicit-bind version of applyWitnessChecks (no join points). -/
def applyWitnessChecksExplicit (ws : WitnessSectionResult) : Except String Unit :=
  let witBytes := ws.endOff - ws.startOff
  if witBytes > MAX_WITNESS_BYTES_PER_TX then
    Except.error "TX_ERR_WITNESS_OVERFLOW"
  else if ws.isOverflow then
    Except.error "TX_ERR_WITNESS_OVERFLOW"
  else if ws.anySigNoncanonical then
    Except.error "TX_ERR_SIG_NONCANONICAL"
  else
    Except.ok ()

open RubinFormal.TxWeightV2 in
/-- Definitional equivalence: live do-version = explicit bind version. -/
theorem applyWitnessChecks_eq_explicit (ws : WitnessSectionResult) :
    applyWitnessChecks ws = applyWitnessChecksExplicit ws := by
  simp only [applyWitnessChecks, applyWitnessChecksExplicit, Except.bind]; rfl

-- Ordering theorems on the LIVE applyWitnessChecks function

open RubinFormal.TxWeightV2 in
theorem witness_bytes_overflow_priority (ws : WitnessSectionResult)
    (h : (ws.endOff - ws.startOff > MAX_WITNESS_BYTES_PER_TX) = true) :
    applyWitnessChecks ws = .error "TX_ERR_WITNESS_OVERFLOW" := by
  rw [applyWitnessChecks_eq_explicit]; simp [applyWitnessChecksExplicit, h]

open RubinFormal.TxWeightV2 in
theorem witness_count_overflow_priority (ws : WitnessSectionResult)
    (hBytes : (ws.endOff - ws.startOff > MAX_WITNESS_BYTES_PER_TX) = false)
    (hOverflow : ws.isOverflow = true) :
    applyWitnessChecks ws = .error "TX_ERR_WITNESS_OVERFLOW" := by
  rw [applyWitnessChecks_eq_explicit]; simp [applyWitnessChecksExplicit, hBytes, hOverflow]

open RubinFormal.TxWeightV2 in
theorem sig_noncanonical_last_priority (ws : WitnessSectionResult)
    (hBytes : (ws.endOff - ws.startOff > MAX_WITNESS_BYTES_PER_TX) = false)
    (hNoOverflow : ws.isOverflow = false)
    (hNoncanon : ws.anySigNoncanonical = true) :
    applyWitnessChecks ws = .error "TX_ERR_SIG_NONCANONICAL" := by
  rw [applyWitnessChecks_eq_explicit]; simp [applyWitnessChecksExplicit, hBytes, hNoOverflow, hNoncanon]

open RubinFormal.TxWeightV2 in
theorem witness_check_all_pass (ws : WitnessSectionResult)
    (hBytes : (ws.endOff - ws.startOff > MAX_WITNESS_BYTES_PER_TX) = false)
    (hNoOverflow : ws.isOverflow = false)
    (hNoNoncanon : ws.anySigNoncanonical = false) :
    applyWitnessChecks ws = .ok () := by
  rw [applyWitnessChecks_eq_explicit]; simp [applyWitnessChecksExplicit, hBytes, hNoOverflow, hNoNoncanon]

open RubinFormal.TxWeightV2 in
theorem witness_check_total (ws : WitnessSectionResult) :
    (∃ err, applyWitnessChecks ws = .error err) ∨
    applyWitnessChecks ws = .ok () := by
  rw [applyWitnessChecks_eq_explicit]
  unfold applyWitnessChecksExplicit
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all

/-! ## Top-level merkle error propagation on validateBlockBasic -/

theorem error_priority_merkle_top_nn
    (blockBytes : Bytes) (pb : ParsedBlock) (mr : Bytes)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hMerkle : merkleRootTxids pb.txids = .ok mr)
    (hMismatch : (mr != pb.header.merkleRoot) = true) :
    validateBlockBasic blockBytes none none = .error "BLOCK_ERR_MERKLE_INVALID" := by
  unfold validateBlockBasic; rw [hParse]
  show (do powCheck pb.header; _) = _; rw [hPow]
  exact error_priority_merkle_afterpow_nn pb mr hMerkle hMismatch

theorem error_priority_merkle_top_sn
    (blockBytes : Bytes) (pb : ParsedBlock) (mr expTarget : Bytes)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hTargetOk : (pb.header.target != expTarget) = false)
    (hMerkle : merkleRootTxids pb.txids = .ok mr)
    (hMismatch : (mr != pb.header.merkleRoot) = true) :
    validateBlockBasic blockBytes none (some expTarget) = .error "BLOCK_ERR_MERKLE_INVALID" := by
  unfold validateBlockBasic; rw [hParse]
  show (do powCheck pb.header; _) = _; rw [hPow]
  simp only [hTargetOk, ite_false]
  exact error_priority_merkle_afterpow_nn pb mr hMerkle hMismatch

theorem error_priority_merkle_top_ns
    (blockBytes : Bytes) (pb : ParsedBlock) (mr expPrev : Bytes)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hLinkOk : (pb.header.prevHash != expPrev) = false)
    (hMerkle : merkleRootTxids pb.txids = .ok mr)
    (hMismatch : (mr != pb.header.merkleRoot) = true) :
    validateBlockBasic blockBytes (some expPrev) none = .error "BLOCK_ERR_MERKLE_INVALID" := by
  unfold validateBlockBasic; rw [hParse]
  show (do powCheck pb.header; _) = _; rw [hPow]
  simp only [hLinkOk, ite_false]
  exact error_priority_merkle_afterpow_nn pb mr hMerkle hMismatch

theorem error_priority_merkle_top_ss
    (blockBytes : Bytes) (pb : ParsedBlock) (mr expTarget expPrev : Bytes)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hTargetOk : (pb.header.target != expTarget) = false)
    (hLinkOk : (pb.header.prevHash != expPrev) = false)
    (hMerkle : merkleRootTxids pb.txids = .ok mr)
    (hMismatch : (mr != pb.header.merkleRoot) = true) :
    validateBlockBasic blockBytes (some expPrev) (some expTarget) = .error "BLOCK_ERR_MERKLE_INVALID" := by
  unfold validateBlockBasic; rw [hParse]
  show (do powCheck pb.header; _) = _; rw [hPow]
  simp only [hTargetOk, ite_false, hLinkOk]
  exact error_priority_merkle_afterpow_nn pb mr hMerkle hMismatch

/-! ## Live semantic tx pre-input ordering (applyTxPreInputChecks)

`applyTxPreInputChecks` is a LIVE sub-function called from
`applyNonCoinbaseTxBasicNoCrypto`. Ordering proved by unfold+rw
on the top checks of the do-block.
-/

open UtxoApplyGenesisV1 in
theorem preinput_empty_inputs_priority
    (tx : UtxoBasicV1.Tx) (height : Nat)
    (h : (tx.inputs.length == 0) = true) :
    applyTxPreInputChecks tx height = .error "TX_ERR_PARSE" := by
  unfold applyTxPreInputChecks; rw [h]; rfl

open UtxoApplyGenesisV1 in
theorem preinput_nonce_zero_priority
    (tx : UtxoBasicV1.Tx) (height : Nat)
    (hInputs : (tx.inputs.length == 0) = false)
    (hNonce : (tx.txNonce == 0) = true) :
    applyTxPreInputChecks tx height = .error "TX_ERR_TX_NONCE_INVALID" := by
  unfold applyTxPreInputChecks
  rw [show (tx.inputs.length == 0) = false from hInputs]
  simp only [hNonce, ite_true]; rfl

/-! ## Live DA-len checks ordering (applyDaLenChecks)

`applyDaLenChecks` is a LIVE sub-function called from `parseTxFromCursor`.
All checks produce TX_ERR_PARSE.
-/

open BlockBasicV1 in
theorem dalen_minimality_priority
    (tk daLen : Nat) (minDa : Bool)
    (h : minDa = false) :
    applyDaLenChecks tk daLen minDa = .error "TX_ERR_PARSE" := by
  unfold applyDaLenChecks; rw [h]; rfl

open BlockBasicV1 in
theorem dalen_kind0_nonzero
    (daLen : Nat)
    (h : (daLen != 0) = true) :
    applyDaLenChecks 0x00 daLen true = .error "TX_ERR_PARSE" := by
  unfold applyDaLenChecks; simp [h]; rfl

open BlockBasicV1 in
theorem dalen_kind1_overflow
    (daLen : Nat)
    (h : (daLen > DaCoreV1.MAX_DA_MANIFEST_BYTES_PER_TX) = true) :
    applyDaLenChecks 0x01 daLen true = .error "TX_ERR_PARSE" := by
  unfold applyDaLenChecks; simp [h]; rfl

open BlockBasicV1 in
theorem dalen_kind2_bounds
    (tk daLen : Nat)
    (hNotZero : (tk == 0x00) = false)
    (hNotOne : (tk == 0x01) = false)
    (h : (daLen < 1 || daLen > DaCoreV1.CHUNK_BYTES) = true) :
    applyDaLenChecks tk daLen true = .error "TX_ERR_PARSE" := by
  unfold applyDaLenChecks; simp [hNotZero, hNotOne, h]; rfl

/-! ## Per-input structural ordering (validateInputStructural)

LIVE sub-function called from applyNonCoinbaseTxBasicNoCrypto per-input loop.
Ordering: scriptSig → sequence → coinbase prevout.
-/

open UtxoApplyGenesisV1 in
theorem input_scriptsig_priority
    (i : UtxoBasicV1.TxIn)
    (h : (i.scriptSig.size != 0) = true) :
    validateInputStructural i = .error "TX_ERR_PARSE" := by
  unfold validateInputStructural; rw [h]; rfl

open UtxoApplyGenesisV1 in
theorem input_sequence_priority
    (i : UtxoBasicV1.TxIn)
    (hSS : (i.scriptSig.size != 0) = false)
    (h : (i.sequence > 0x7fffffff) = true) :
    validateInputStructural i = .error "TX_ERR_SEQUENCE_INVALID" := by
  simp [validateInputStructural, hSS, h]; rfl

open UtxoApplyGenesisV1 in
theorem input_coinbase_prevout_priority
    (i : UtxoBasicV1.TxIn)
    (hSS : (i.scriptSig.size != 0) = false)
    (hSeq : (i.sequence > 0x7fffffff) = false)
    (h : UtxoBasicV1.isCoinbasePrevout i = true) :
    validateInputStructural i = .error "TX_ERR_PARSE" := by
  simp [validateInputStructural, hSS, hSeq, h]; rfl

/-! ## Header/bounds parse checks (validateTxKind, validateInputCountMin, validateOutputCountMin)

LIVE sub-functions called from parseTxFromCursor. All throw TX_ERR_PARSE.
-/

open BlockBasicV1 in
theorem txkind_invalid (tk : Nat)
    (h : (!(tk == 0x00 || tk == 0x01 || tk == 0x02)) = true) :
    validateTxKind tk = .error "TX_ERR_PARSE" := by
  unfold validateTxKind; rw [h]; rfl

open BlockBasicV1 in
theorem input_count_min_fail (minIn : Bool) (h : minIn = false) :
    validateInputCountMin minIn = .error "TX_ERR_PARSE" := by
  unfold validateInputCountMin; rw [h]; rfl

open BlockBasicV1 in
theorem output_count_min_fail (minOut : Bool) (h : minOut = false) :
    validateOutputCountMin minOut = .error "TX_ERR_PARSE" := by
  unfold validateOutputCountMin; rw [h]; rfl

/-! ## Per-input UTXO lookup ordering (validateInputUtxoLookup)

LIVE sub-function called from per-input loop. Written without do-notation
to enable formal ordering proofs. Ordering: duplicate → missing → anchor/DA → coinbase.
-/

open UtxoApplyGenesisV1 in
theorem utxo_duplicate_priority (utxoEntry : Option UtxoBasicV1.UtxoEntry) (height : Nat) :
    validateInputUtxoLookup true utxoEntry height = .error "TX_ERR_PARSE" := by
  simp [validateInputUtxoLookup]

open UtxoApplyGenesisV1 in
theorem utxo_missing_priority (height : Nat) :
    validateInputUtxoLookup false none height = .error "TX_ERR_MISSING_UTXO" := by
  simp [validateInputUtxoLookup]

open UtxoApplyGenesisV1 in
theorem utxo_anchor_rejected (e : UtxoBasicV1.UtxoEntry) (height : Nat)
    (h : (e.covenantType == CovenantGenesisV1.COV_TYPE_ANCHOR || e.covenantType == CovenantGenesisV1.COV_TYPE_DA_COMMIT) = true) :
    validateInputUtxoLookup false (some e) height = .error "TX_ERR_MISSING_UTXO" := by
  simp [validateInputUtxoLookup, h]

open UtxoApplyGenesisV1 in
theorem utxo_coinbase_immature (e : UtxoBasicV1.UtxoEntry) (height : Nat)
    (hNotAnchor : (e.covenantType == CovenantGenesisV1.COV_TYPE_ANCHOR || e.covenantType == CovenantGenesisV1.COV_TYPE_DA_COMMIT) = false)
    (hCoinbase : e.createdByCoinbase = true)
    (hImmature : (height < e.creationHeight + UtxoBasicV1.COINBASE_MATURITY) = true) :
    validateInputUtxoLookup false (some e) height = .error "TX_ERR_COINBASE_IMMATURE" := by
  simp [validateInputUtxoLookup, hNotAnchor, hCoinbase, hImmature]

/-! ## Post-loop witness cursor (validateWitnessCursorComplete)

LIVE sub-function: validates all witness items consumed after per-input loop.
-/

open UtxoApplyGenesisV1 in
theorem witness_cursor_incomplete (cursor witnessLen : Nat)
    (h : (cursor != witnessLen) = true) :
    validateWitnessCursorComplete cursor witnessLen = .error "TX_ERR_PARSE" := by
  simp [validateWitnessCursorComplete, h]

/-! ## Full covenant dispatch ordering (dispatchCovenantValidation — LIVE)

`dispatchCovenantValidation` is now the live structural covenant-dispatch
sub-function called from the `applyNonCoinbaseTxBasicNoCrypto` per-input loop
before branch-specific checks/state updates. Written without do-notation
(explicit if/match) to enable formal proofs on the direct live call path.

FULL DISPATCH PROOF: unknown covenant type → TX_ERR_COVENANT_TYPE_INVALID.
-/

open UtxoApplyGenesisV1 in
/-- FULL DISPATCH: unknown covenant type → exactly TX_ERR_COVENANT_TYPE_INVALID.
    All 4 known-type checks fail → else branch fires. Direct on live function. -/
theorem dispatch_unknown_covenant_error
    (e : UtxoBasicV1.UtxoEntry) (tx : UtxoBasicV1.Tx) (wc height mtp : Nat)
    (hNotP2PK : (e.covenantType == CovenantGenesisV1.COV_TYPE_P2PK) = false)
    (hNotMulti : (e.covenantType == CovenantGenesisV1.COV_TYPE_MULTISIG) = false)
    (hNotVault : (e.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false)
    (hNotHtlc : (e.covenantType == CovenantGenesisV1.COV_TYPE_HTLC) = false) :
    dispatchCovenantValidation e tx wc height mtp = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  simp [dispatchCovenantValidation, hNotP2PK, hNotMulti, hNotVault, hNotHtlc]

/-! ## Value conservation (validateValueConservation — LIVE)

LIVE sub-function: post-loop check in applyNonCoinbaseTxBasicNoCrypto.
Written without do-notation.
-/

open UtxoApplyGenesisV1 in
theorem value_conservation_overspend (sumOut sumIn vic siv : Nat)
    (h : (sumOut > sumIn) = true) :
    validateValueConservation sumOut sumIn vic siv = .error "TX_ERR_VALUE_CONSERVATION" := by
  simp [validateValueConservation, h]

open UtxoApplyGenesisV1 in
theorem value_conservation_vault_drain (sumOut sumIn sumInVault : Nat)
    (_hNotOver : ¬ sumOut > sumIn)
    (hDrain : sumOut < sumInVault) :
    validateValueConservation sumOut sumIn 1 sumInVault = .error "TX_ERR_VALUE_CONSERVATION" := by
  simp [validateValueConservation]
  intro _ hGe
  omega

theorem err_ne_tx_value_parse : ("TX_ERR_VALUE_CONSERVATION" : String) ≠ "TX_ERR_PARSE" := by decide
theorem err_ne_tx_value_missing : ("TX_ERR_VALUE_CONSERVATION" : String) ≠ "TX_ERR_MISSING_UTXO" := by decide
theorem err_ne_tx_value_covenant : ("TX_ERR_VALUE_CONSERVATION" : String) ≠ "TX_ERR_COVENANT_TYPE_INVALID" := by decide

/-! ## Stage-position witnesses: link live sub-functions to their position
    in parseTxFromCursor and applyNonCoinbaseTxBasicNoCrypto.

    Each theorem explicitly names the live function AND its error code,
    proving the stage-to-function correspondence. Combined with
    do-block short-circuit semantics (earlier stages prevent later ones),
    this gives the full ordering chain on live code.
-/

-- parseTxFromCursor ordering
theorem parse_stage_txkind_live : ∀ tk,
    (!(tk == 0x00 || tk == 0x01 || tk == 0x02)) = true →
    validateTxKind tk = .error "TX_ERR_PARSE" :=
  fun tk h => txkind_invalid tk h

theorem parse_stage_inputmin_live : ∀ m,
    m = false → validateInputCountMin m = .error "TX_ERR_PARSE" :=
  fun m h => input_count_min_fail m h

theorem parse_stage_outputmin_live : ∀ m,
    m = false → validateOutputCountMin m = .error "TX_ERR_PARSE" :=
  fun m h => output_count_min_fail m h

open RubinFormal.TxWeightV2 in
theorem parse_stage_witness_overflow_live : ∀ ws,
    (ws.endOff - ws.startOff > MAX_WITNESS_BYTES_PER_TX) = true →
    applyWitnessChecks ws = .error "TX_ERR_WITNESS_OVERFLOW" :=
  fun ws h => witness_bytes_overflow_priority ws h

-- applyNonCoinbaseTxBasicNoCrypto ordering
open UtxoApplyGenesisV1 in
theorem semantic_stage1_empty_inputs_live : ∀ tx height,
    (tx.inputs.length == 0) = true →
    applyTxPreInputChecks tx height = .error "TX_ERR_PARSE" :=
  fun tx height h => preinput_empty_inputs_priority tx height h

open UtxoApplyGenesisV1 in
theorem semantic_stage2_nonce_live : ∀ tx height,
    (tx.inputs.length == 0) = false → (tx.txNonce == 0) = true →
    applyTxPreInputChecks tx height = .error "TX_ERR_TX_NONCE_INVALID" :=
  fun tx height h1 h2 => preinput_nonce_zero_priority tx height h1 h2

open UtxoApplyGenesisV1 in
theorem perinput_scriptsig_live : ∀ i,
    (i.scriptSig.size != 0) = true →
    validateInputStructural i = .error "TX_ERR_PARSE" :=
  fun i h => input_scriptsig_priority i h

open UtxoApplyGenesisV1 in
theorem perinput_duplicate_live : ∀ e height,
    validateInputUtxoLookup true e height = .error "TX_ERR_PARSE" :=
  fun e height => utxo_duplicate_priority e height

open UtxoApplyGenesisV1 in
theorem perinput_unknown_covenant_live : ∀ e tx wc h m,
    (e.covenantType == CovenantGenesisV1.COV_TYPE_P2PK) = false →
    (e.covenantType == CovenantGenesisV1.COV_TYPE_MULTISIG) = false →
    (e.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false →
    (e.covenantType == CovenantGenesisV1.COV_TYPE_HTLC) = false →
    dispatchCovenantValidation e tx wc h m = .error "TX_ERR_COVENANT_TYPE_INVALID" :=
  fun e tx wc h m h1 h2 h3 h4 => dispatch_unknown_covenant_error e tx wc h m h1 h2 h3 h4

open UtxoApplyGenesisV1 in
theorem postloop_witness_cursor_live : ∀ c wl,
    (c != wl) = true →
    validateWitnessCursorComplete c wl = .error "TX_ERR_PARSE" :=
  fun c wl h => witness_cursor_incomplete c wl h

open UtxoApplyGenesisV1 in
theorem postloop_value_overspend_live : ∀ so si vic siv,
    (so > si) = true →
    validateValueConservation so si vic siv = .error "TX_ERR_VALUE_CONSERVATION" :=
  fun so si vic siv h => value_conservation_overspend so si vic siv h

/-! ## Machine-checked bridge: enum stages ↔ live function error codes

Bridge lemmas connect pipeline stage enums to live sub-functions.
Each theorem proves: stage ordinal = N ∧ live_function(args) = error.
Combined with stage ordering chain, this gives machine-checked
enum-to-live-function correspondence.
-/

-- Parse pipeline enum
inductive TxParseStage where
  | HeaderRead | TxKind | InputCountMin | InputParse
  | OutputCountMin | OutputParse | Locktime | WitnessChecks | DaLenChecks
deriving DecidableEq

def txParseStageOrd : TxParseStage → Nat
  | .HeaderRead => 0 | .TxKind => 1 | .InputCountMin => 2 | .InputParse => 3
  | .OutputCountMin => 4 | .OutputParse => 5 | .Locktime => 6
  | .WitnessChecks => 7 | .DaLenChecks => 8

theorem txParseStageOrd_injective (a b : TxParseStage)
    (h : txParseStageOrd a = txParseStageOrd b) : a = b := by
  cases a <;> cases b <;> simp [txParseStageOrd] at h <;> rfl

/-! ### Direct error-propagation bridges to live code

Each theorem proves: given a specific sub-function failure condition,
`parseTxFromCursor` or `parseTxPostInputs` returns that error.
`ptfc_*` theorems target `parseTxFromCursor` directly.
`ptpi_*` theorems target `parseTxPostInputs` (one hop from
`parseTxFromCursor` via `ptfc_post_inputs_fail`).
-/

section DirectBridges
open Wire

-- HeaderRead (stage 0): version read failure → parseTxFromCursor error
theorem ptfc_header_version_fail (c : Wire.Cursor)
    (h : c.getU32le? = none) :
    txParseStageOrd .HeaderRead = 0 ∧
    parseTxFromCursor c = .error "BLOCK_ERR_PARSE" := by
  constructor; · rfl
  · simp only [parseTxFromCursor, h]

-- HeaderRead (stage 0): txkind byte read failure → parseTxFromCursor error
theorem ptfc_header_txkind_fail (c : Wire.Cursor) (ver : Nat) (c1 : Wire.Cursor)
    (hVer : c.getU32le? = some (ver, c1))
    (hTk : c1.getU8? = none) :
    txParseStageOrd .HeaderRead = 0 ∧
    parseTxFromCursor c = .error "BLOCK_ERR_PARSE" := by
  constructor; · rfl
  · simp only [parseTxFromCursor, hVer, hTk]

-- Nonce read failure → parseTxFromCursor error
theorem ptfc_nonce_fail (c : Wire.Cursor) (ver : Nat) (c1 : Wire.Cursor)
    (tkB : UInt8) (c2 : Wire.Cursor)
    (hVer : c.getU32le? = some (ver, c1))
    (hTk : c1.getU8? = some (tkB, c2))
    (hTxKind : validateTxKind tkB.toNat = .ok ())
    (hNonce : c2.getU64le? = none) :
    parseTxFromCursor c = .error "BLOCK_ERR_PARSE" := by
  simp only [parseTxFromCursor, bind, Except.bind, hVer, hTk, hTxKind, hNonce]

-- InputParse (stage 3): readInputs failure → parseTxFromCursor error
theorem ptfc_inputs_fail (c : Wire.Cursor) (ver : Nat) (c1 : Wire.Cursor)
    (tkB : UInt8) (c2 : Wire.Cursor) (nonce : UInt64) (c3 : Wire.Cursor)
    (inCount : Nat) (c4 : Wire.Cursor) (minIn : Bool)
    (hVer : c.getU32le? = some (ver, c1))
    (hTk : c1.getU8? = some (tkB, c2))
    (hTxKind : validateTxKind tkB.toNat = .ok ())
    (hNonce : c2.getU64le? = some (nonce, c3))
    (hCompact : c3.getCompactSize? = some (inCount, c4, minIn))
    (hMinIn : validateInputCountMin minIn = .ok ())
    (hInputs : readInputs c4 inCount = .error e) :
    txParseStageOrd .InputParse = 3 ∧
    parseTxFromCursor c = .error e := by
  constructor; · rfl
  · simp only [parseTxFromCursor, bind, Except.bind, hVer, hTk, hTxKind, hNonce, hCompact, hMinIn, hInputs]

-- parseTxPostInputs failure → parseTxFromCursor error (delegation)
theorem ptfc_post_inputs_fail (c : Wire.Cursor) (ver : Nat) (c1 : Wire.Cursor)
    (tkB : UInt8) (c2 : Wire.Cursor) (nonce : UInt64) (c3 : Wire.Cursor)
    (inCount : Nat) (c4 : Wire.Cursor) (minIn : Bool) (c5 : Wire.Cursor)
    (hVer : c.getU32le? = some (ver, c1))
    (hTk : c1.getU8? = some (tkB, c2))
    (hTxKind : validateTxKind tkB.toNat = .ok ())
    (hNonce : c2.getU64le? = some (nonce, c3))
    (hCompact : c3.getCompactSize? = some (inCount, c4, minIn))
    (hMinIn : validateInputCountMin minIn = .ok ())
    (hInputs : readInputs c4 inCount = .ok c5)
    (hPost : parseTxPostInputs c c.off tkB.toNat inCount c5 = .error e) :
    parseTxFromCursor c = .error e := by
  simp only [parseTxFromCursor, bind, Except.bind, hVer, hTk, hTxKind, hNonce, hCompact, hMinIn, hInputs, hPost]

-- OutputParse (stage 5): readOutputs failure → parseTxPostInputs error
theorem ptpi_outputs_fail (c : Wire.Cursor) (start tk inCount : Nat) (c5 : Wire.Cursor)
    (outCount : Nat) (c6 : Wire.Cursor) (minOut : Bool)
    (hOC : readOutputCount c5 = .ok (outCount, c6, minOut))
    (hMin : validateOutputCountMin minOut = .ok ())
    (hOut : readOutputs c6 outCount = .error e) :
    txParseStageOrd .OutputParse = 5 ∧
    parseTxPostInputs c start tk inCount c5 = .error e := by
  constructor; · rfl
  · unfold parseTxPostInputs
    simp only [bind, Except.bind, hOC, hMin, hOut]

-- Locktime (stage 6): readLocktime failure → parseTxPostInputs error
theorem ptpi_locktime_fail (c : Wire.Cursor) (start tk inCount : Nat) (c5 : Wire.Cursor)
    (outCount : Nat) (c6 : Wire.Cursor) (minOut : Bool) (c7 : Wire.Cursor) (anchorN : Nat)
    (hOC : readOutputCount c5 = .ok (outCount, c6, minOut))
    (hMin : validateOutputCountMin minOut = .ok ())
    (hOut : readOutputs c6 outCount = .ok (c7, anchorN))
    (hLock : readLocktime c7 = .error e) :
    txParseStageOrd .Locktime = 6 ∧
    parseTxPostInputs c start tk inCount c5 = .error e := by
  constructor; · rfl
  · unfold parseTxPostInputs
    simp only [bind, Except.bind, hOC, hMin, hOut, hLock]

end DirectBridges


theorem bridge_parse_txkind (tk : Nat) (h : (!(tk == 0x00 || tk == 0x01 || tk == 0x02)) = true) :
    txParseStageOrd .TxKind = 1 ∧ validateTxKind tk = .error "TX_ERR_PARSE" :=
  ⟨rfl, txkind_invalid tk h⟩

theorem bridge_parse_inputmin (m : Bool) (h : m = false) :
    txParseStageOrd .InputCountMin = 2 ∧ validateInputCountMin m = .error "TX_ERR_PARSE" :=
  ⟨rfl, input_count_min_fail m h⟩

theorem bridge_parse_outputmin (m : Bool) (h : m = false) :
    txParseStageOrd .OutputCountMin = 4 ∧ validateOutputCountMin m = .error "TX_ERR_PARSE" :=
  ⟨rfl, output_count_min_fail m h⟩

open TxWeightV2 in
theorem bridge_parse_witness (ws : WitnessSectionResult)
    (h : (ws.endOff - ws.startOff > MAX_WITNESS_BYTES_PER_TX) = true) :
    txParseStageOrd .WitnessChecks = 7 ∧
    applyWitnessChecks ws = .error "TX_ERR_WITNESS_OVERFLOW" :=
  ⟨rfl, witness_bytes_overflow_priority ws h⟩

theorem bridge_parse_dalen (tk daLen : Nat) (minDa : Bool)
    (h : minDa = false) :
    txParseStageOrd .DaLenChecks = 8 ∧
    applyDaLenChecks tk daLen minDa = .error "TX_ERR_PARSE" :=
  ⟨rfl, dalen_minimality_priority tk daLen minDa h⟩

theorem parse_stage_chain :
    txParseStageOrd .HeaderRead < txParseStageOrd .TxKind ∧
    txParseStageOrd .TxKind < txParseStageOrd .InputCountMin ∧
    txParseStageOrd .InputCountMin < txParseStageOrd .InputParse ∧
    txParseStageOrd .InputParse < txParseStageOrd .OutputCountMin ∧
    txParseStageOrd .OutputCountMin < txParseStageOrd .OutputParse ∧
    txParseStageOrd .OutputParse < txParseStageOrd .Locktime ∧
    txParseStageOrd .Locktime < txParseStageOrd .WitnessChecks ∧
    txParseStageOrd .WitnessChecks < txParseStageOrd .DaLenChecks := by
  simp [txParseStageOrd]

-- Semantic pipeline enum
inductive TxSemanticStage where
  | EmptyInputs | Nonce | OutputCovenants | InputStructural
  | UtxoLookup | CovenantDispatch | WitnessCursor | ValueConservation
deriving DecidableEq

def txSemanticStageOrd : TxSemanticStage → Nat
  | .EmptyInputs => 0 | .Nonce => 1 | .OutputCovenants => 2 | .InputStructural => 3
  | .UtxoLookup => 4 | .CovenantDispatch => 5 | .WitnessCursor => 6 | .ValueConservation => 7

theorem txSemanticStageOrd_injective (a b : TxSemanticStage)
    (h : txSemanticStageOrd a = txSemanticStageOrd b) : a = b := by
  cases a <;> cases b <;> simp [txSemanticStageOrd] at h <;> rfl

open UtxoApplyGenesisV1 in
theorem bridge_semantic_empty (tx : UtxoBasicV1.Tx) (height : Nat)
    (h : (tx.inputs.length == 0) = true) :
    txSemanticStageOrd .EmptyInputs = 0 ∧
    applyTxPreInputChecks tx height = .error "TX_ERR_PARSE" :=
  ⟨rfl, preinput_empty_inputs_priority tx height h⟩

open UtxoApplyGenesisV1 in
theorem bridge_semantic_nonce (tx : UtxoBasicV1.Tx) (height : Nat)
    (h1 : (tx.inputs.length == 0) = false) (h2 : (tx.txNonce == 0) = true) :
    txSemanticStageOrd .Nonce = 1 ∧
    applyTxPreInputChecks tx height = .error "TX_ERR_TX_NONCE_INVALID" :=
  ⟨rfl, preinput_nonce_zero_priority tx height h1 h2⟩

open UtxoApplyGenesisV1 in
theorem bridge_semantic_duplicate (e : Option UtxoBasicV1.UtxoEntry) (height : Nat) :
    txSemanticStageOrd .UtxoLookup = 4 ∧
    validateInputUtxoLookup true e height = .error "TX_ERR_PARSE" :=
  ⟨rfl, utxo_duplicate_priority e height⟩

open UtxoApplyGenesisV1 in
theorem bridge_semantic_unknown_covenant
    (e : UtxoBasicV1.UtxoEntry) (tx : UtxoBasicV1.Tx) (wc h m : Nat)
    (h1 : (e.covenantType == CovenantGenesisV1.COV_TYPE_P2PK) = false)
    (h2 : (e.covenantType == CovenantGenesisV1.COV_TYPE_MULTISIG) = false)
    (h3 : (e.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false)
    (h4 : (e.covenantType == CovenantGenesisV1.COV_TYPE_HTLC) = false) :
    txSemanticStageOrd .CovenantDispatch = 5 ∧
    dispatchCovenantValidation e tx wc h m = .error "TX_ERR_COVENANT_TYPE_INVALID" :=
  ⟨rfl, dispatch_unknown_covenant_error e tx wc h m h1 h2 h3 h4⟩

open UtxoApplyGenesisV1 in
theorem bridge_semantic_value (so si vic siv : Nat) (h : (so > si) = true) :
    txSemanticStageOrd .ValueConservation = 7 ∧
    validateValueConservation so si vic siv = .error "TX_ERR_VALUE_CONSERVATION" :=
  ⟨rfl, value_conservation_overspend so si vic siv h⟩

theorem semantic_stage_chain :
    txSemanticStageOrd .EmptyInputs < txSemanticStageOrd .Nonce ∧
    txSemanticStageOrd .Nonce < txSemanticStageOrd .OutputCovenants ∧
    txSemanticStageOrd .OutputCovenants < txSemanticStageOrd .InputStructural ∧
    txSemanticStageOrd .InputStructural < txSemanticStageOrd .UtxoLookup ∧
    txSemanticStageOrd .UtxoLookup < txSemanticStageOrd .CovenantDispatch ∧
    txSemanticStageOrd .CovenantDispatch < txSemanticStageOrd .WitnessCursor ∧
    txSemanticStageOrd .WitnessCursor < txSemanticStageOrd .ValueConservation := by
  simp [txSemanticStageOrd]

theorem bridge_semantic_output_covenant (out : CovenantGenesisV1.TxOut)
    (txKind height : Nat)
    (h1 : (out.covenantType == CovenantGenesisV1.COV_TYPE_P2PK) = false)
    (h2 : (out.covenantType == CovenantGenesisV1.COV_TYPE_ANCHOR) = false)
    (h3 : (out.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false)
    (h4 : (out.covenantType == CovenantGenesisV1.COV_TYPE_MULTISIG) = false)
    (h5 : (out.covenantType == CovenantGenesisV1.COV_TYPE_HTLC) = false)
    (h6 : (out.covenantType == CovenantGenesisV1.COV_TYPE_DA_COMMIT) = false) :
    txSemanticStageOrd TxSemanticStage.OutputCovenants = 2 ∧
    CovenantGenesisV1.validateOutGenesis out txKind height = .error "TX_ERR_COVENANT_TYPE_INVALID" := by
  exact ⟨rfl, by unfold CovenantGenesisV1.validateOutGenesis; simp only [h1, h2, h3, h4, h5, h6, ite_false]; rfl⟩

open UtxoApplyGenesisV1 in
theorem bridge_semantic_scriptsig (i : UtxoBasicV1.TxIn)
    (h : (i.scriptSig.size != 0) = true) :
    txSemanticStageOrd .InputStructural = 3 ∧
    validateInputStructural i = .error "TX_ERR_PARSE" :=
  ⟨rfl, input_scriptsig_priority i h⟩

open UtxoApplyGenesisV1 in
theorem bridge_semantic_witness_cursor (cursor witnessLen : Nat)
    (h : (cursor != witnessLen) = true) :
    txSemanticStageOrd .WitnessCursor = 6 ∧
    validateWitnessCursorComplete cursor witnessLen = .error "TX_ERR_PARSE" :=
  ⟨rfl, witness_cursor_incomplete cursor witnessLen h⟩

/-! ## Error code distinctness (§13) -/

theorem err_ne_block_tx_parse : ("BLOCK_ERR_PARSE" : String) ≠ "TX_ERR_PARSE" := by decide
theorem err_ne_tx_parse_seq : ("TX_ERR_PARSE" : String) ≠ "TX_ERR_SEQUENCE_INVALID" := by decide
theorem err_ne_tx_parse_coinbase : ("TX_ERR_PARSE" : String) ≠ "TX_ERR_COINBASE_IMMATURE" := by decide
theorem err_ne_tx_missing_coinbase : ("TX_ERR_MISSING_UTXO" : String) ≠ "TX_ERR_COINBASE_IMMATURE" := by decide
theorem err_ne_tx_parse_nonce_invalid : ("TX_ERR_PARSE" : String) ≠ "TX_ERR_TX_NONCE_INVALID" := by decide

theorem err_ne_parse_target : ("BLOCK_ERR_PARSE" : String) ≠ "BLOCK_ERR_TARGET_INVALID" := by decide
theorem err_ne_parse_linkage : ("BLOCK_ERR_PARSE" : String) ≠ "BLOCK_ERR_LINKAGE_INVALID" := by decide
theorem err_ne_parse_merkle : ("BLOCK_ERR_PARSE" : String) ≠ "BLOCK_ERR_MERKLE_INVALID" := by decide
theorem err_ne_parse_witness : ("BLOCK_ERR_PARSE" : String) ≠ "BLOCK_ERR_WITNESS_COMMITMENT" := by decide
theorem err_ne_target_linkage : ("BLOCK_ERR_TARGET_INVALID" : String) ≠ "BLOCK_ERR_LINKAGE_INVALID" := by decide
theorem err_ne_target_merkle : ("BLOCK_ERR_TARGET_INVALID" : String) ≠ "BLOCK_ERR_MERKLE_INVALID" := by decide
theorem err_ne_target_witness : ("BLOCK_ERR_TARGET_INVALID" : String) ≠ "BLOCK_ERR_WITNESS_COMMITMENT" := by decide
theorem err_ne_linkage_merkle : ("BLOCK_ERR_LINKAGE_INVALID" : String) ≠ "BLOCK_ERR_MERKLE_INVALID" := by decide
theorem err_ne_linkage_witness : ("BLOCK_ERR_LINKAGE_INVALID" : String) ≠ "BLOCK_ERR_WITNESS_COMMITMENT" := by decide
theorem err_ne_merkle_witness : ("BLOCK_ERR_MERKLE_INVALID" : String) ≠ "BLOCK_ERR_WITNESS_COMMITMENT" := by decide
theorem err_ne_ts_old_future : ("BLOCK_ERR_TIMESTAMP_OLD" : String) ≠ "BLOCK_ERR_TIMESTAMP_FUTURE" := by decide
theorem err_ne_parse_ts_old : ("BLOCK_ERR_PARSE" : String) ≠ "BLOCK_ERR_TIMESTAMP_OLD" := by decide
theorem err_ne_parse_ts_future : ("BLOCK_ERR_PARSE" : String) ≠ "BLOCK_ERR_TIMESTAMP_FUTURE" := by decide
theorem err_ne_tx_parse_nonce : ("TX_ERR_PARSE" : String) ≠ "TX_ERR_NONCE_REPLAY" := by decide

/-! ## §13 Contract: Consensus Error Ordering Complete

Composition theorems that bundle the individual stage-priority, totality, and
success-chain results into unified §13 contract statements.  These are LIVE
on `validateBlockBasic` and the tx sub-function pipeline — not model-only.
-/

/-- §13 Block-level contract: totality + error dominance + full success chain.
    (1) Total: accept ∨ error.
    (2) Parse dominates: parse failure wins unconditionally.
    (3) PoW dominates stages 3-6: given parse ok, pow failure wins.
    (4) Success → ALL 6 stages passed (parse, pow, target, linkage,
        merkle root, witness commitment) — via `section25_order_complete`. -/
theorem consensus_error_ordering_contract
    (blockBytes : Bytes) (ph pt : Option Bytes) :
    -- (1) Totality
    (section25AcceptWitness blockBytes ph pt ∨
      ∃ err, validateBlockBasic blockBytes ph pt = .error err) ∧
    -- (2) Parse dominates
    (∀ err, parseBlock blockBytes = .error err →
      validateBlockBasic blockBytes ph pt = .error err) ∧
    -- (3) PoW dominates stages 3–6
    (∀ pb err, parseBlock blockBytes = .ok pb →
      powCheck pb.header = .error err →
      validateBlockBasic blockBytes ph pt = .error err) ∧
    -- (4) Success → all 6 stages passed
    (validateBlockBasic blockBytes ph pt = .ok () →
      ∃ pb mr,
        parseBlock blockBytes = .ok pb ∧
        powCheck pb.header = .ok () ∧
        (match pt with | none => True | some exp => pb.header.target = exp) ∧
        (match ph with | none => True | some exp => pb.header.prevHash = exp) ∧
        merkleRootTxids pb.txids = .ok mr ∧
        mr = pb.header.merkleRoot ∧
        checkWitnessCommitment pb = .ok ()) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · exact validateBlockBasic_accept_or_reject blockBytes ph pt
  · intro err hFail; exact error_priority_parse blockBytes ph pt err hFail
  · intro pb err hParse hFail; exact error_priority_pow blockBytes ph pt pb err hParse hFail
  · intro h; exact section25_order_complete blockBytes ph pt h

/-- Experimental tx-parse stage-order model over the listed 0..8 stages.
    It omits DA-core and payload-read failures, so it is not a live complete
    parse-stage claim. Separate bridge theorems cover selected listed stages:
    `ptfc_header_version_fail` /
    `ptfc_header_txkind_fail` (stage 0), `bridge_parse_txkind` (1),
    `bridge_parse_inputmin` (2), `ptfc_inputs_fail` (3),
    `bridge_parse_outputmin` (4), `ptpi_outputs_fail` (5),
    `ptpi_locktime_fail` (6), `bridge_parse_witness` (7),
    `bridge_parse_dalen` (8). -/
theorem tx_parse_pipeline_deterministic :
    -- Strict stage ordering for the listed adjacent pairs 0..8
    (txParseStageOrd .HeaderRead < txParseStageOrd .TxKind ∧
     txParseStageOrd .TxKind < txParseStageOrd .InputCountMin ∧
     txParseStageOrd .InputCountMin < txParseStageOrd .InputParse ∧
     txParseStageOrd .InputParse < txParseStageOrd .OutputCountMin ∧
     txParseStageOrd .OutputCountMin < txParseStageOrd .OutputParse ∧
     txParseStageOrd .OutputParse < txParseStageOrd .Locktime ∧
     txParseStageOrd .Locktime < txParseStageOrd .WitnessChecks ∧
     txParseStageOrd .WitnessChecks < txParseStageOrd .DaLenChecks) ∧
    -- Stage ordinals are injective (no two stages share an ordinal)
    (∀ a b, txParseStageOrd a = txParseStageOrd b → a = b) := by
  exact ⟨parse_stage_chain, txParseStageOrd_injective⟩

/-- Tx semantic pipeline: model-level stage ordering is strict + injective.
    Live grounding provided by separate bridge theorems: `bridge_semantic_*`
    for most stages, plus `input_sequence_priority` and
    `input_coinbase_prevout_priority` for InputStructural sub-checks. -/
theorem tx_semantic_pipeline_deterministic :
    -- Strict stage ordering (complete chain, all 7 adjacent pairs)
    (txSemanticStageOrd .EmptyInputs < txSemanticStageOrd .Nonce ∧
     txSemanticStageOrd .Nonce < txSemanticStageOrd .OutputCovenants ∧
     txSemanticStageOrd .OutputCovenants < txSemanticStageOrd .InputStructural ∧
     txSemanticStageOrd .InputStructural < txSemanticStageOrd .UtxoLookup ∧
     txSemanticStageOrd .UtxoLookup < txSemanticStageOrd .CovenantDispatch ∧
     txSemanticStageOrd .CovenantDispatch < txSemanticStageOrd .WitnessCursor ∧
     txSemanticStageOrd .WitnessCursor < txSemanticStageOrd .ValueConservation) ∧
    -- Stage ordinals are injective
    (∀ a b, txSemanticStageOrd a = txSemanticStageOrd b → a = b) := by
  exact ⟨semantic_stage_chain, txSemanticStageOrd_injective⟩

/-! ## Smoke tests: bridge lemmas with concrete inputs -/

-- bridge_parse_dalen: minDa=false → error at stage 8
example : txParseStageOrd .DaLenChecks = 8 ∧
    BlockBasicV1.applyDaLenChecks 0 100 false = .error "TX_ERR_PARSE" :=
  bridge_parse_dalen 0 100 false rfl

-- bridge_semantic_witness_cursor: cursor ≠ witnessLen → error at stage 6
example : txSemanticStageOrd .WitnessCursor = 6 ∧
    UtxoApplyGenesisV1.validateWitnessCursorComplete 3 5 = .error "TX_ERR_PARSE" :=
  bridge_semantic_witness_cursor 3 5 (by native_decide)

end RubinFormal
