import RubinFormal.CriticalInvariants
import RubinFormal.MerkleV2
import RubinFormal.MerkleStructure
import RubinFormal.UtxoBasicV1
import RubinFormal.TxWirePrefixLemmas
import RubinFormal.TxWireRoundtrip
import Std.Tactic.Omega

set_option maxHeartbeats 8000000

/-!
# TXID/WTXID Behavioral Proofs (§8)

Proves domain tag separation for TXID and WTXID merkle tree construction.
-/

namespace RubinFormal

open Merkle
open UtxoBasicV1

/-- TXID leaf tag (0x00) differs from WTXID leaf tag (0x02). -/
theorem txid_wtxid_tag_distinct :
    (0x00 : UInt8) ≠ (0x02 : UInt8) := by native_decide

/-- TXID leaf tag (0x00) differs from TXID node tag (0x01). -/
theorem txid_leaf_node_tag_distinct :
    (0x00 : UInt8) ≠ (0x01 : UInt8) := by native_decide

/-- WTXID leaf tag (0x02) differs from WTXID node tag (0x03). -/
theorem wtxid_leaf_node_tag_distinct :
    (0x02 : UInt8) ≠ (0x03 : UInt8) := by native_decide

/-- All four merkle domain tags are pairwise distinct. -/
theorem all_merkle_tags_distinct :
    (0x00 : UInt8) ≠ 0x01 ∧ (0x00 : UInt8) ≠ 0x02 ∧ (0x00 : UInt8) ≠ 0x03 ∧
    (0x01 : UInt8) ≠ 0x02 ∧ (0x01 : UInt8) ≠ 0x03 ∧
    (0x02 : UInt8) ≠ 0x03 := by native_decide

/-- CompactSize always emits at least one byte. -/
private theorem compactSize_size_pos (n : Nat) :
    0 < (RubinFormal.WireEnc.compactSize n).size := by
  by_cases h1 : n < 0xfd
  · rw [compactSize_size_one n h1]
    decide
  · by_cases h2 : n ≤ 0xffff
    · rw [compactSize_size_three n h1 h2]
      decide
    · by_cases h3 : n ≤ 0xffffffff
      · rw [compactSize_size_five n h1 h2 h3]
        decide
      · rw [compactSize_size_nine n h1 h2 h3]
        decide

/-- Witness serialization always contributes at least the witness-count CompactSize byte,
    even when the witness list is empty. -/
private theorem serializeWitness_size_pos (wit : List WitnessItem) :
    0 < (serializeWitness wit).size := by
  unfold serializeWitness
  rw [ByteArray.size_append]
  have hCount : 0 < (RubinFormal.WireEnc.compactSize wit.length).size :=
    compactSize_size_pos wit.length
  omega

private theorem bytes_empty_append (bs : Bytes) : ByteArray.empty ++ bs = bs := by
  apply ByteArray.ext
  simp [ByteArray.append_data, ByteArray.empty_data, Array.nil_append]

/-- The txid preimage (`TxCoreBytes`) and the wtxid preimage (`TxBytes`) are
    structurally distinct for every serialized transaction, because the full
    wire encoding always retains at least the witness-count and payload-length
    CompactSize markers after the core bytes. -/
theorem txid_wtxid_payloads_distinct (tx : Tx) :
    serializeTxCore tx ≠ serializeTx tx := by
  apply bytearray_ne_of_size_lt
  unfold serializeTxCore serializeTx serializeTxAfterNonce serializeWitness
  repeat rw [ByteArray.size_append]
  have hWitnessCount : 0 < (RubinFormal.WireEnc.compactSize tx.witness.length).size :=
    compactSize_size_pos tx.witness.length
  have hDaLen : 0 < (RubinFormal.WireEnc.compactSize tx.daPayloadLen).size :=
    compactSize_size_pos tx.daPayloadLen
  omega

/-- Witness-empty transactions are still serialized with an explicit
    `CompactSize(0)` witness-count marker before the DA payload length field. -/
theorem txid_wtxid_witness_empty_serialization_shape
    (tx : Tx) (hEmpty : tx.witness = []) :
    serializeTx tx =
      serializeTxCore tx ++
        RubinFormal.WireEnc.compactSize 0 ++
        RubinFormal.WireEnc.compactSize tx.daPayloadLen ++
        tx.daPayload := by
  simp [serializeTx, serializeTxCore, serializeTxAfterNonce,
    serializeWitness, serializeWitnessItems, concatBytes,
    cursor_bytes_left_assoc, hEmpty, bytes_empty_append]

/-- Section-level identifier-domain contract:
    the canonical txid and wtxid preimages are structurally distinct for every
    serialized transaction, and the tagged Merkle leaf-preimage domains remain
    disjoint. Distinct digests across those distinct preimages remain an explicit
    SHA3 assumption boundary. -/
theorem txid_wtxid_identifier_domain_contract
    (tx : Tx) :
    serializeTxCore tx ≠ serializeTx tx ∧
    Merkle.txidLeafPreimage (serializeTxCore tx) ≠
      Merkle.wtxidLeafPreimage (serializeTx tx) := by
  constructor
  · exact txid_wtxid_payloads_distinct tx
  · exact Merkle.merkle_tag_equivalence_leaf_domains_disjoint
      (serializeTxCore tx) (serializeTx tx)

/-- Canonical txid digest emitted from the stripped serializer boundary. -/
def canonicalTxidDigest (tx : Tx) : Bytes :=
  SHA3.sha3_256 (serializeTxCore tx)

/-- Canonical wtxid digest emitted from the full serializer boundary. -/
def canonicalWtxidDigest (tx : Tx) : Bytes :=
  SHA3.sha3_256 (serializeTx tx)

/-- Honest crypto-boundary reduction for txid/wtxid uniqueness:
    if the live txid and wtxid digests for the same serialized transaction are
    equal, then SHA3-256 collides on distinct executable preimages. This is a
    reduction theorem, not an axiom-free impossibility proof. -/
theorem txid_wtxid_digest_collision_reduces_to_sha3_collision
    (tx : Tx)
    (hEq : canonicalTxidDigest tx = canonicalWtxidDigest tx) :
    SHA3.sha3_256 (serializeTxCore tx) = SHA3.sha3_256 (serializeTx tx) ∧
    serializeTxCore tx ≠ serializeTx tx := by
  refine ⟨?_, txid_wtxid_payloads_distinct tx⟩
  simpa [canonicalTxidDigest, canonicalWtxidDigest] using hEq

end RubinFormal
