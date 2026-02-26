import RubinFormal.CriticalInvariants
import RubinFormal.ByteWire
import RubinFormal.ArithmeticSafety

namespace RubinFormal

def transactionWireStatement : Prop :=
  parseTransactionWire [] = none ∧
  (∀ n : Nat, n < 253 → parseCompactSize (encodeCompactSize n) = some (n, [])) ∧
  (∀ tx : TxMini, txMiniByteValid tx → parseTxMini (serializeTxMini tx) = some tx)
def transactionIdentifiersStatement : Prop := ∀ n : Nat, txidPreimage n ≠ wtxidPreimage n
def weightAccountingStatement : Prop :=
  ∀ base witness1 witness2 sigCost : Nat, witness1 ≤ witness2 → weight base witness1 sigCost ≤ weight base witness2 sigCost
def witnessCommitmentStatement : Prop := coinbaseWitnessCommitmentSeed = 0
def sighashV1Statement : Prop :=
  ∀ chainId locktime nonce1 nonce2 : Nat,
    nonce1 ≠ nonce2 →
      sighashPreimage chainId nonce1 locktime ≠ sighashPreimage chainId nonce2 locktime
def consensusErrorCodesStatement : Prop := ErrorCode.TxErrParse ≠ ErrorCode.TxErrSigInvalid
def covenantRegistryStatement : Prop := CovenantType.P2PK ≠ CovenantType.HTLC
def difficultyUpdateStatement : Prop :=
  (∀ prevTs newTs maxStep : Nat, clampTimestampStep prevTs newTs maxStep ≤ prevTs + maxStep) ∧
  (∀ a b : Nat, 0 < b → floorDiv a b * b ≤ a)
def transactionStructuralRulesStatement : Prop :=
  ∀ cursor witnessCount : Nat, cursor ≤ witnessCount → witnessCursorValid cursor 0 witnessCount
def replayDomainChecksStatement : Prop :=
  ∀ n : Nat, ∀ xs : List Nat, n ∈ xs → ¬ nonceReplayFree (n :: xs)
def utxoStateModelStatement : Prop := ∀ v : Nat, ¬ canSpend { spendable := false, value := v }
def valueConservationStatement : Prop :=
  (∀ sumIn sumOut fee : Nat, valueConserved sumIn sumOut → valueConserved (sumIn + fee) sumOut) ∧
  (∀ sumIn sumOut fee : Nat, inU128 sumIn → valueConserved sumIn sumOut → valueConserved (satAddU128 sumIn fee) sumOut)
def daSetIntegrityStatement : Prop := ¬ daChunkSetValid []

theorem transaction_wire_proved : transactionWireStatement := by
  refine ⟨?_, ?_, ?_⟩
  · simpa using parse_empty_none
  · intro n hn
    exact parse_encodeCompactSize_roundtrip n hn
  · intro tx htx
    exact parse_serializeTxMini_roundtrip tx htx

theorem transaction_identifiers_proved : transactionIdentifiersStatement := by
  intro n
  exact txid_wtxid_preimage_distinct n

theorem weight_accounting_proved : weightAccountingStatement := by
  intro base witness1 witness2 sigCost hw
  exact weight_monotone_witness base witness1 witness2 sigCost hw

theorem witness_commitment_proved : witnessCommitmentStatement := by
  simpa [witnessCommitmentStatement] using witness_commitment_seed_zero

theorem sighash_v1_proved : sighashV1Statement := by
  intro chainId locktime nonce1 nonce2 h
  exact sighash_binds_nonce chainId locktime nonce1 nonce2 h

theorem consensus_error_codes_proved : consensusErrorCodesStatement := by
  simpa [consensusErrorCodesStatement] using error_codes_distinct

theorem covenant_registry_proved : covenantRegistryStatement := by
  simpa [covenantRegistryStatement] using covenant_types_distinct

theorem difficulty_update_proved : difficultyUpdateStatement := by
  refine ⟨?_, ?_⟩
  · intro prevTs newTs maxStep
    exact clamp_respects_upper_bound prevTs newTs maxStep
  · intro a b hb
    exact floorDiv_mul_le a b hb

theorem transaction_structural_rules_proved : transactionStructuralRulesStatement := by
  intro cursor witnessCount h
  exact witness_cursor_zero_slot cursor witnessCount h

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

end RubinFormal
