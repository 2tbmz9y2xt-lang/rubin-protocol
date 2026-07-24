import Std
import RubinFormal.Types
import RubinFormal.SHA3_256

namespace RubinFormal

namespace Merkle

def taggedLeafPreimage (tag : UInt8) (id : Bytes) : Bytes :=
  (ByteArray.empty.push tag) ++ id

def taggedNodePreimage (tag : UInt8) (l r : Bytes) : Bytes :=
  (ByteArray.empty.push tag) ++ l ++ r

def taggedLeafHash (tag : UInt8) (id : Bytes) : Bytes :=
  SHA3.sha3_256 (taggedLeafPreimage tag id)

def taggedNodeHash (tag : UInt8) (l r : Bytes) : Bytes :=
  SHA3.sha3_256 (taggedNodePreimage tag l r)

def txidLeafPreimage (txid : Bytes) : Bytes :=
  taggedLeafPreimage 0x00 txid

def txidNodePreimage (l r : Bytes) : Bytes :=
  taggedNodePreimage 0x01 l r

def wtxidLeafPreimage (wtxid : Bytes) : Bytes :=
  taggedLeafPreimage 0x02 wtxid

def wtxidNodePreimage (l r : Bytes) : Bytes :=
  taggedNodePreimage 0x03 l r

def txidLeafHash (txid : Bytes) : Bytes :=
  taggedLeafHash 0x00 txid

def txidNodeHash (l r : Bytes) : Bytes :=
  taggedNodeHash 0x01 l r

def wtxidLeafHash (wtxid : Bytes) : Bytes :=
  taggedLeafHash 0x02 wtxid

def wtxidNodeHash (l r : Bytes) : Bytes :=
  taggedNodeHash 0x03 l r

def leafHash (txid : Bytes) : Bytes :=
  txidLeafHash txid

def nodeHash (l r : Bytes) : Bytes :=
  txidNodeHash l r

def reduceLevel (xs : List Bytes) : List Bytes :=
  match xs with
  | [] => []
  | [x] => [x]
  | x :: y :: rest => nodeHash x y :: reduceLevel rest

private theorem reduceLevel_length_le_internal (xs : List Bytes) :
    (reduceLevel xs).length ≤ xs.length := by
  cases xs with
  | nil =>
      simp [reduceLevel]
  | cons x xs =>
      cases xs with
      | nil =>
          simp [reduceLevel]
      | cons y rest =>
          have hLe : (reduceLevel rest).length ≤ rest.length := reduceLevel_length_le_internal rest
          simp [reduceLevel]
          omega

private theorem reduceLevel_length_lt_internal (xs : List Bytes) (h : 2 ≤ xs.length) :
    (reduceLevel xs).length < xs.length := by
  cases xs with
  | nil =>
      simp at h
  | cons x xs =>
      cases xs with
      | nil =>
          simp at h
      | cons y rest =>
          have hLe : (reduceLevel rest).length ≤ rest.length := reduceLevel_length_le_internal rest
          simp [reduceLevel]
          omega

def merkleRootFromLevel : List Bytes → Option Bytes
  | [] => none
  | [r] => some r
  | x :: y :: rest => merkleRootFromLevel (reduceLevel (x :: y :: rest))
termination_by level => level.length
decreasing_by
  simpa using
    reduceLevel_length_lt_internal (x :: y :: rest)
      (Nat.succ_le_succ (Nat.succ_le_succ (Nat.zero_le _)))

def merkleRoot (txids : List Bytes) : Option Bytes :=
  merkleRootFromLevel (txids.map leafHash)

end Merkle
end RubinFormal
