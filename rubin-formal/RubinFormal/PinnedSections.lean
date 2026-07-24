import RubinFormal.CriticalInvariants
import RubinFormal.ByteWireLegacy
import RubinFormal.ArithmeticSafety
import RubinFormal.SubsidyV1
import RubinFormal.DevnetProperties
import RubinFormal.SighashV1
import RubinFormal.CovenantGenesisV1
import RubinFormal.CovenantRegistryExhaustive
import RubinFormal.WitnessCommitmentV1
import RubinFormal.TxIdBehavioral

namespace RubinFormal

/-- Bootstrap-only transaction-wire statement.
    The `CompactSize` and `TxMini` conjuncts intentionally use the legacy toy model in
    `ByteWireLegacy`; byte-accurate wire claims come from `ByteWireV2` and conformance replay,
    as tracked in `proof_coverage.json`. -/
def transactionWireStatement : Prop :=
  parseTransactionWire [] = none ∧
  (∀ n : Nat, n < 253 →
    ByteWireLegacy.parseCompactSizeToy (ByteWireLegacy.encodeCompactSizeToy n) = some (n, [])) ∧
  (∀ tx : ByteWireLegacy.TxMini, ByteWireLegacy.txMiniByteValid tx →
    ByteWireLegacy.parseTxMini (ByteWireLegacy.serializeTxMini tx) = some tx)
/-- §8 identifier boundary surface.
    (1) `TxCoreBytes` and `TxBytes` are structurally distinct for every
        serialized transaction because the full wire encoding always retains
        witness-count / payload-length markers after the core bytes.
    (2) The witness-empty lane is covered explicitly: the full bytes still carry
        a `CompactSize(0)` witness-count marker before the DA payload length. -/
def transactionIdentifiersStatement : Prop :=
  (∀ tx : UtxoBasicV1.Tx,
    UtxoBasicV1.serializeTxCore tx ≠ UtxoBasicV1.serializeTx tx) ∧
  (∀ tx : UtxoBasicV1.Tx,
    tx.witness = [] →
      UtxoBasicV1.serializeTx tx =
        UtxoBasicV1.serializeTxCore tx ++
          RubinFormal.WireEnc.compactSize 0 ++
          RubinFormal.WireEnc.compactSize tx.daPayloadLen ++
          tx.daPayload)
def weightAccountingStatement : Prop :=
  ∀ base witness1 witness2 sigCost : Nat, witness1 ≤ witness2 → weight base witness1 sigCost ≤ weight base witness2 sigCost
/-- v3 (D08-F02 fix): standalone witness-commitment semantics.
    (1) Witness merkle construction zeroes the coinbase slot.
    (2) The isolated witness-commitment step accepts iff the coinbase anchor
        matches the prefixed witness-merkle commitment.
    (3) Once parse/pow/target/linkage/merkle gates pass, `validateBlockBasic`
        reduces exactly to this witness-commitment step. -/
def witnessCommitmentStatement : Prop :=
  (∀ (coinbaseWtxid : Bytes) (rest : List Bytes),
    BlockBasicV1.witnessMerkleRootWtxids (coinbaseWtxid :: rest) =
      BlockBasicV1.merkleRootTagged
        (BlockBasicV1.coinbaseWitnessReservedValue :: rest) 0x02 0x03) ∧
  (∀ (pb : BlockBasicV1.ParsedBlock) (witnessRoot gotCommit : Bytes),
    BlockBasicV1.witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot →
    BlockBasicV1.findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit →
    (BlockBasicV1.checkWitnessCommitment pb = .ok () ↔
      gotCommit = BlockBasicV1.witnessCommitmentHash witnessRoot)) ∧
  (∀ (blockBytes : Bytes)
      (expectedPrevHash expectedTarget : Option Bytes)
      (pb : BlockBasicV1.ParsedBlock),
    BlockBasicV1.parseBlock blockBytes = .ok pb →
    BlockBasicV1.powCheck pb.header = .ok () →
    (match expectedTarget with
    | none => True
    | some exp => pb.header.target = exp) →
    (match expectedPrevHash with
    | none => True
    | some exp => pb.header.prevHash = exp) →
    BlockBasicV1.merkleRootTxids pb.txids = .ok pb.header.merkleRoot →
    BlockBasicV1.validateBlockBasic blockBytes expectedPrevHash expectedTarget =
      BlockBasicV1.checkWitnessCommitment pb)
/-- v3 (D08-F04/D08-F10 fix): spec-level sighash commitment completeness.
    (1) Fixed encoding sizes (8 and 4 bytes) remain canonical.
    (2) Selector helpers for `ALL/NONE/SINGLE/ANYONECANPAY` choose the intended
        input/output commitment scope over pre-hashed transaction components.
    (3) Distinct declared transaction fields (`version`, `locktime`, input context,
        output context including `sighash_type`) yield distinct preimage-frame parts.
    This is a structural theorem surface over the hashed preimage builder; it does
    not claim SHA3 collision resistance or full tx-level equivalence for every §12 path. -/
def sighashV1Statement : Prop :=
  (∀ n : Nat, (SighashV1.u64le n).size = 8) ∧
  (∀ n : Nat, (SighashV1.u32le n).size = 4) ∧
  (∀ allInputs currentInput : Bytes,
    SighashV1.selectHashPrevouts SighashV1.SIGHASH_ALL allInputs currentInput = some allInputs) ∧
  (∀ allInputs currentInput : Bytes,
    SighashV1.selectHashPrevouts SighashV1.SIGHASH_ALL_ANYONECANPAY allInputs currentInput = some currentInput) ∧
  (∀ allInputs currentInput : Bytes,
    SighashV1.selectHashSequences SighashV1.SIGHASH_NONE allInputs currentInput = some allInputs) ∧
  (∀ allInputs currentInput : Bytes,
    SighashV1.selectHashSequences SighashV1.SIGHASH_NONE_ANYONECANPAY allInputs currentInput = some currentInput) ∧
  (∀ inputIndex outputCount : Nat, ∀ allOutputs selectedOutput emptyHash : Bytes,
    SighashV1.selectHashOutputs SighashV1.SIGHASH_ALL inputIndex outputCount allOutputs selectedOutput emptyHash =
      some allOutputs) ∧
  (∀ inputIndex outputCount : Nat, ∀ allOutputs selectedOutput emptyHash : Bytes,
    SighashV1.selectHashOutputs SighashV1.SIGHASH_NONE inputIndex outputCount allOutputs selectedOutput emptyHash =
      some emptyHash) ∧
  (∀ inputIndex outputCount : Nat, ∀ allOutputs selectedOutput emptyHash : Bytes,
    inputIndex < outputCount →
    SighashV1.selectHashOutputs SighashV1.SIGHASH_SINGLE inputIndex outputCount allOutputs selectedOutput emptyHash =
      some selectedOutput) ∧
  (∀ inputIndex outputCount : Nat, ∀ allOutputs selectedOutput emptyHash : Bytes,
    ¬ inputIndex < outputCount →
    SighashV1.selectHashOutputs SighashV1.SIGHASH_SINGLE inputIndex outputCount allOutputs selectedOutput emptyHash =
      some emptyHash) ∧
  (∀ a b : SighashV1.SighashPreimageFrame,
    a.versionLE ≠ b.versionLE →
    SighashV1.buildPreimageFrameParts a ≠ SighashV1.buildPreimageFrameParts b) ∧
  (∀ a b : SighashV1.SighashPreimageFrame,
    a.locktimeLE ≠ b.locktimeLE →
    SighashV1.buildPreimageFrameParts a ≠ SighashV1.buildPreimageFrameParts b) ∧
  (∀ a b : SighashV1.SighashPreimageFrame,
    a.inputContextView ≠ b.inputContextView →
    SighashV1.buildPreimageFrameParts a ≠ SighashV1.buildPreimageFrameParts b) ∧
  (∀ a b : SighashV1.SighashPreimageFrame,
    a.outputContextView ≠ b.outputContextView →
    SighashV1.buildPreimageFrameParts a ≠ SighashV1.buildPreimageFrameParts b)
def consensusErrorCodesStatement : Prop := ErrorCode.TxErrParse ≠ ErrorCode.TxErrSigInvalid
/-- Bounded Section 14 static tag-disposition surface. It does not assert output
    acceptance, activation/deployment behavior, descriptor semantics, spend rules,
    cryptography, or client equivalence. -/
def covenantRegistryStatement : Prop :=
  ∀ tag : Nat, tag < 0x10000 → section14DispositionCase tag (covenantDisposition tag)
def difficultyUpdateStatement : Prop :=
  (∀ prevTs newTs maxStep : Nat, clampTimestampStep prevTs newTs maxStep ≤ prevTs + maxStep) ∧
  (∀ a b : Nat, 0 < b → floorDiv a b * b ≤ a)
/-- v2 (F-13 fix): strengthened from zero-slot only to general case + advance property.
    (1) General validity: any cursor + slots ≤ witnessCount is valid.
    (2) Advance: consuming one slot preserves validity (operational loop invariant). -/
def transactionStructuralRulesStatement : Prop :=
  (∀ cursor slots witnessCount : Nat,
    cursor + slots ≤ witnessCount → witnessCursorValid cursor slots witnessCount) ∧
  (∀ cursor slots witnessCount : Nat,
    witnessCursorValid cursor (slots + 1) witnessCount →
      witnessCursorValid (cursor + 1) slots witnessCount)
def replayDomainChecksStatement : Prop :=
  ∀ n : Nat, ∀ xs : List Nat, n ∈ xs → ¬ nonceReplayFree (n :: xs)
def utxoStateModelStatement : Prop := ∀ v : Nat, ¬ canSpend { spendable := false, value := v }
def valueConservationStatement : Prop :=
  (∀ sumIn sumOut fee : Nat, valueConserved sumIn sumOut → valueConserved (sumIn + fee) sumOut) ∧
  (∀ sumIn sumOut fee : Nat, inU128 sumIn → valueConserved sumIn sumOut → valueConserved (satAddU128 sumIn fee) sumOut)
def daSetIntegrityStatement : Prop := ¬ daChunkSetValid []
-- §19.1: subsidy arithmetic fits in machine integer types (PR #420).
def subsidyU128SafetyStatement : Prop :=
  (∀ h ag : Nat, SubsidyV1.blockSubsidy h ag ≤ SubsidyV1.MINEABLE_CAP) ∧
  (∀ h ag : Nat, SubsidyV1.blockSubsidy h ag ≤ maxU64) ∧
  (∀ h ag fees : Nat, ag ≤ SubsidyV1.MINEABLE_CAP → fees ≤ maxU64 →
    ag + SubsidyV1.blockSubsidy h ag + fees ≤ maxU128)
/-- F-05 fix: ByteWireV2 cursor advancement + TxErr distinctness.
    (1) getU8? advances offset by 1.
    (2) getBytes? advances offset by n.
    (3) All TxErr constructors are pairwise distinct. -/
def byteWireV2CursorStatement : Prop :=
  (∀ c : Wire.Cursor, ∀ b : UInt8, ∀ c' : Wire.Cursor,
    c.getU8? = some (b, c') → c'.off = c.off + 1) ∧
  (∀ c : Wire.Cursor, ∀ n : Nat, ∀ bs : Bytes, ∀ c' : Wire.Cursor,
    c.getBytes? n = some (bs, c') → c'.off = c.off + n) ∧
  (Wire.TxErr.parse ≠ Wire.TxErr.witnessOverflow ∧
   Wire.TxErr.parse ≠ Wire.TxErr.sigAlgInvalid ∧
   Wire.TxErr.parse ≠ Wire.TxErr.sigNoncanonical ∧
   Wire.TxErr.witnessOverflow ≠ Wire.TxErr.sigAlgInvalid ∧
   Wire.TxErr.witnessOverflow ≠ Wire.TxErr.sigNoncanonical ∧
   Wire.TxErr.sigAlgInvalid ≠ Wire.TxErr.sigNoncanonical)
/-- F-17 fix: HTLC timelock enforcement — refund path blocked before expiry.
    (1) Height-lock: blockHeight < lockValue → timelock NOT met.
    (2) Timestamp-lock: blockMtp < lockValue → timelock NOT met.
    (3) Lock modes are distinct (height ≠ timestamp). -/
def htlcTimelockStatement : Prop :=
  (∀ lockValue blockHeight blockMtp : Nat, blockHeight < lockValue →
    CovenantGenesisV1.htlcTimelockMet CovenantGenesisV1.LOCK_MODE_HEIGHT lockValue blockHeight blockMtp = false) ∧
  (∀ lockValue blockHeight blockMtp : Nat, blockMtp < lockValue →
    CovenantGenesisV1.htlcTimelockMet CovenantGenesisV1.LOCK_MODE_TIMESTAMP lockValue blockHeight blockMtp = false) ∧
  (CovenantGenesisV1.LOCK_MODE_HEIGHT ≠ CovenantGenesisV1.LOCK_MODE_TIMESTAMP)
def devnetGenesisValidUtxoStatement : Prop :=
  Conformance.devnetGenesisVectorPass devnetGenesisVector0 = true
def devnetSubsidyBoundedStatement : Prop :=
  ∀ n : Nat, accumulateSubsidy n ≤ SubsidyV1.MINEABLE_CAP
def devnetChainIdDeterministicStatement : Prop :=
  ∀ g1 g2 : Bytes, g1 = g2 → deriveChainId g1 = deriveChainId g2
def devnetCoinbaseMaturityStatement : Prop :=
  Conformance.devnetMaturityVectorPass devnetMaturityVector0 = true

theorem transaction_wire_proved : transactionWireStatement := by
  refine ⟨?_, ?_, ?_⟩
  · simpa using parse_empty_none
  · intro n hn
    exact ByteWireLegacy.parse_encodeCompactSizeToy_roundtrip n hn
  · intro tx htx
    exact ByteWireLegacy.parse_serializeTxMini_roundtrip tx htx

theorem transaction_identifiers_proved : transactionIdentifiersStatement := by
  refine ⟨?_, ?_⟩
  · intro tx
    exact txid_wtxid_payloads_distinct tx
  · intro tx hEmpty
    exact txid_wtxid_witness_empty_serialization_shape tx hEmpty

theorem weight_accounting_proved : weightAccountingStatement := by
  intro base witness1 witness2 sigCost hw
  exact weight_monotone_witness base witness1 witness2 sigCost hw

theorem witness_commitment_proved : witnessCommitmentStatement := by
  refine ⟨?_, ?_, ?_⟩
  · intro coinbaseWtxid rest
    exact WitnessCommitmentV1.witnessMerkleRootWtxids_rewrites_coinbase_slot coinbaseWtxid rest
  · intro pb witnessRoot gotCommit hRoot hCommit
    exact WitnessCommitmentV1.checkWitnessCommitment_ok_iff
      pb witnessRoot gotCommit hRoot hCommit
  · intro blockBytes expectedPrevHash expectedTarget pb hParse hPow hTarget hPrev hMerkle
    exact WitnessCommitmentV1.validateBlockBasic_witness_stage
      blockBytes expectedPrevHash expectedTarget pb hParse hPow hTarget hPrev hMerkle

theorem sighash_v1_proved : sighashV1Statement := by
  refine ⟨fun _ => rfl, fun _ => rfl, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro allInputs currentInput
    exact SighashV1.selectHashPrevouts_all_commits_all_inputs allInputs currentInput
  · intro allInputs currentInput
    exact SighashV1.selectHashPrevouts_anyonecanpay_commits_current_input allInputs currentInput
  · intro allInputs currentInput
    exact SighashV1.selectHashSequences_all_commits_all_inputs allInputs currentInput
  · intro allInputs currentInput
    exact SighashV1.selectHashSequences_anyonecanpay_commits_current_input allInputs currentInput
  · intro inputIndex outputCount allOutputs selectedOutput emptyHash
    exact SighashV1.selectHashOutputs_all_commits_all_outputs inputIndex outputCount allOutputs selectedOutput emptyHash
  · intro inputIndex outputCount allOutputs selectedOutput emptyHash
    exact SighashV1.selectHashOutputs_none_commits_no_outputs inputIndex outputCount allOutputs selectedOutput emptyHash
  · intro inputIndex outputCount allOutputs selectedOutput emptyHash h
    exact SighashV1.selectHashOutputs_single_commits_selected_output inputIndex outputCount allOutputs selectedOutput emptyHash h
  · intro inputIndex outputCount allOutputs selectedOutput emptyHash h
    exact SighashV1.selectHashOutputs_single_oob_commits_empty inputIndex outputCount allOutputs selectedOutput emptyHash h
  · intro a b h hEq; exact h (congrArg SighashV1.SighashPreimageFrame.versionLE
      (SighashV1.buildPreimageFrameParts_injective a b hEq))
  · intro a b h hEq; exact h (congrArg SighashV1.SighashPreimageFrame.locktimeLE
      (SighashV1.buildPreimageFrameParts_injective a b hEq))
  · intro a b h hEq; exact h (congrArg SighashV1.SighashPreimageFrame.inputContextView
      (SighashV1.buildPreimageFrameParts_injective a b hEq))
  · intro a b h hEq; exact h (congrArg SighashV1.SighashPreimageFrame.outputContextView
      (SighashV1.buildPreimageFrameParts_injective a b hEq))

theorem consensus_error_codes_proved : consensusErrorCodesStatement := by
  simpa [consensusErrorCodesStatement] using error_codes_distinct

theorem covenant_registry_proved : covenantRegistryStatement := by
  intro tag hU16
  exact covenantDispositionComplete tag hU16

theorem difficulty_update_proved : difficultyUpdateStatement := by
  refine ⟨?_, ?_⟩
  · intro prevTs newTs maxStep
    exact clamp_respects_upper_bound prevTs newTs maxStep
  · intro a b hb
    exact floorDiv_mul_le a b hb

theorem transaction_structural_rules_proved : transactionStructuralRulesStatement := by
  refine ⟨?_, ?_⟩
  · intro cursor slots witnessCount h
    exact witness_cursor_valid_general cursor slots witnessCount h
  · intro cursor slots witnessCount h
    exact witness_cursor_advance cursor slots witnessCount h

theorem replay_domain_checks_proved : replayDomainChecksStatement := by
  intro n xs h
  exact duplicate_nonce_not_replay_free n xs h

theorem utxo_state_model_proved : utxoStateModelStatement := by
  intro v
  exact non_spendable_cannot_spend v

theorem value_conservation_proved : valueConservationStatement := by
  refine ⟨?_, ?_⟩
  · intro sumIn sumOut fee h
    exact value_conservation_with_extra_input sumIn sumOut fee h
  · intro sumIn sumOut fee hU128 hCons
    unfold valueConserved at *
    exact Nat.le_trans hCons (satAddU128_preserves_lower_bound sumIn fee hU128)

theorem da_set_integrity_proved : daSetIntegrityStatement := by
  simpa [daSetIntegrityStatement] using da_chunk_set_requires_nonempty

theorem subsidy_u128_safety_proved : subsidyU128SafetyStatement := by
  refine ⟨?_, ?_, ?_⟩
  · exact blockSubsidy_bounded
  · exact blockSubsidy_in_u64
  · intro h ag fees hAg hFees
    exact subsidy_accumulation_in_u128 h ag fees hAg hFees

theorem byte_wire_v2_cursor_proved : byteWireV2CursorStatement := by
  refine ⟨?_, ?_, ?_⟩
  · exact Wire.Cursor.getU8_advances
  · exact Wire.Cursor.getBytes_advances
  · exact Wire.txerr_all_distinct

theorem htlc_timelock_proved : htlcTimelockStatement := by
  refine ⟨?_, ?_, ?_⟩
  · exact CovenantGenesisV1.htlc_height_lock_enforcement
  · exact CovenantGenesisV1.htlc_timestamp_lock_enforcement
  · exact CovenantGenesisV1.htlc_lock_modes_distinct

theorem devnet_genesis_valid_utxo_proved : devnetGenesisValidUtxoStatement := by
  simpa [devnetGenesisValidUtxoStatement] using thm_devnet_genesis_valid_utxo

theorem devnet_subsidy_bounded_proved : devnetSubsidyBoundedStatement := by
  intro n
  exact thm_devnet_subsidy_bounded n

theorem devnet_chainid_deterministic_proved : devnetChainIdDeterministicStatement := by
  intro g1 g2 h
  exact thm_devnet_chainid_deterministic g1 g2 h

theorem devnet_coinbase_maturity_proved : devnetCoinbaseMaturityStatement := by
  simpa [devnetCoinbaseMaturityStatement] using thm_devnet_coinbase_maturity

end RubinFormal
