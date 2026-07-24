import Std
import RubinFormal.MerkleV2

namespace RubinFormal

namespace Merkle

theorem merkleRoot_singleton (txid : Bytes) :
    merkleRoot [txid] = some (leafHash txid) := by
  simp [merkleRoot]
  rfl

theorem reduceLevel_singleton (x : Bytes) :
    reduceLevel [x] = [x] := rfl

theorem reduceLevel_pair (x y : Bytes) :
    reduceLevel [x, y] = [nodeHash x y] := rfl

theorem reduceLevel_length_le (xs : List Bytes) :
    (reduceLevel xs).length ≤ xs.length := by
  cases xs with
  | nil =>
      simp [reduceLevel]
  | cons x xs =>
      cases xs with
      | nil =>
          simp [reduceLevel]
      | cons y rest =>
          have hLe : (reduceLevel rest).length ≤ rest.length := reduceLevel_length_le rest
          simp [reduceLevel]
          omega

theorem reduceLevel_length_lt (xs : List Bytes) (h : 2 ≤ xs.length) :
    (reduceLevel xs).length < xs.length := by
  cases xs with
  | nil =>
      simp at h
  | cons x xs =>
      cases xs with
      | nil =>
          simp at h
      | cons y rest =>
          have hLe : (reduceLevel rest).length ≤ rest.length := reduceLevel_length_le rest
          simp [reduceLevel]
          omega

theorem merkleRoot_termination_measure (level : List Bytes) (h : 2 ≤ level.length) :
    (reduceLevel level).length < level.length := by
  exact reduceLevel_length_lt level h

theorem leafTag_ne_nodeTag : (0x00 : UInt8) ≠ 0x01 := by
  decide

theorem leafHash_txid_tag_equivalence (txid : Bytes) :
    leafHash txid = SHA3.sha3_256 (txidLeafPreimage txid) := by
  rfl

theorem nodeHash_txid_tag_equivalence (l r : Bytes) :
    nodeHash l r = SHA3.sha3_256 (txidNodePreimage l r) := by
  rfl

theorem leafHash_nodeHash_tag_domain (txid l r : Bytes) :
    leafHash txid = SHA3.sha3_256 (txidLeafPreimage txid) ∧
    nodeHash l r = SHA3.sha3_256 (txidNodePreimage l r) := by
  constructor <;> rfl

theorem wtxidLeafHash_wtxidNodeHash_tag_domain (wtxid l r : Bytes) :
    wtxidLeafHash wtxid = SHA3.sha3_256 (wtxidLeafPreimage wtxid) ∧
    wtxidNodeHash l r = SHA3.sha3_256 (wtxidNodePreimage l r) := by
  constructor <;> rfl

private theorem array_push_empty_append_get_zero (tag : UInt8) (rest : Array UInt8) :
    (Array.push #[] tag ++ rest)[0]? = some tag := by
  show (Array.push #[] tag ++ rest).data[0]? = some tag
  rw [Array.append_data]
  simp [Array.push, Array.data]

private theorem tagged_leaf_first_byte (tag : UInt8) (rest : Bytes) :
    (ByteArray.push ByteArray.empty tag ++ rest).data[0]? = some tag := by
  simp [ByteArray.append, ByteArray.push, ByteArray.empty]
  exact array_push_empty_append_get_zero tag rest.data

private theorem tagged_node_first_byte (tag : UInt8) (l r : Bytes) :
    (ByteArray.push ByteArray.empty tag ++ l ++ r).data[0]? = some tag := by
  simp [ByteArray.append, ByteArray.push, ByteArray.empty]
  -- Shape: (Array.push #[] tag ++ l.data ++ r.data)[0]?
  -- (a ++ b ++ c) = (a ++ b) ++ c by Array.append_assoc
  rw [Array.append_assoc]
  exact array_push_empty_append_get_zero tag (l.data ++ r.data)

theorem merkle_tag_equivalence_leaf_domains_disjoint (txid wtxid : Bytes) :
    txidLeafPreimage txid ≠ wtxidLeafPreimage wtxid := by
  intro h
  have h0 := congrArg (fun bs => bs.data[0]?) h
  simp only [txidLeafPreimage, wtxidLeafPreimage, taggedLeafPreimage] at h0
  rw [tagged_leaf_first_byte 0x00 txid, tagged_leaf_first_byte 0x02 wtxid] at h0
  cases h0

theorem merkle_tag_equivalence_node_domains_disjoint
    (txLeft txRight witLeft witRight : Bytes) :
    txidNodePreimage txLeft txRight ≠ wtxidNodePreimage witLeft witRight := by
  intro h
  have h0 := congrArg (fun bs => bs.data[0]?) h
  simp only [txidNodePreimage, wtxidNodePreimage, taggedNodePreimage] at h0
  rw [tagged_node_first_byte 0x01 txLeft txRight,
      tagged_node_first_byte 0x03 witLeft witRight] at h0
  cases h0

theorem merkle_tag_equivalence_leaf_collision_reduces_to_sha3_collision
    (txid wtxid : Bytes)
    (h : txidLeafHash txid = wtxidLeafHash wtxid) :
    SHA3.sha3_256 (txidLeafPreimage txid) = SHA3.sha3_256 (wtxidLeafPreimage wtxid) ∧
    txidLeafPreimage txid ≠ wtxidLeafPreimage wtxid := by
  exact ⟨h, merkle_tag_equivalence_leaf_domains_disjoint txid wtxid⟩

theorem merkle_tag_equivalence_node_collision_reduces_to_sha3_collision
    (txLeft txRight witLeft witRight : Bytes)
    (h : txidNodeHash txLeft txRight = wtxidNodeHash witLeft witRight) :
    SHA3.sha3_256 (txidNodePreimage txLeft txRight) =
        SHA3.sha3_256 (wtxidNodePreimage witLeft witRight) ∧
    txidNodePreimage txLeft txRight ≠ wtxidNodePreimage witLeft witRight := by
  exact ⟨h, merkle_tag_equivalence_node_domains_disjoint txLeft txRight witLeft witRight⟩

end Merkle
end RubinFormal
