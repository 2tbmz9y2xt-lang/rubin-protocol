import Std
import RubinFormal.SHA3_256

namespace RubinFormal

abbrev Bytes := ByteArray

namespace Merkle

def leafHash (txid : Bytes) : Bytes :=
  SHA3.sha3_256 ((ByteArray.empty.push 0x00) ++ txid)

def nodeHash (l r : Bytes) : Bytes :=
  SHA3.sha3_256 ((ByteArray.empty.push 0x01) ++ l ++ r)

partial def reduceLevel (xs : List Bytes) : List Bytes :=
  match xs with
  | [] => []
  | [x] => [x]
  | x :: y :: rest => nodeHash x y :: reduceLevel rest

partial def merkleRoot (txids : List Bytes) : Option Bytes :=
  match txids with
  | [] => none
  | _ =>
    let mut level := txids.map leafHash
    while level.length > 1 do
      level := reduceLevel level
    match level with
    | [r] => some r
    | _ => none

end Merkle
end RubinFormal

