import RubinFormal.Types
import RubinFormal.SHA3_256

namespace RubinFormal

namespace Merkle

def leafHash (txid : Bytes) : Bytes :=
  SHA3.sha3_256 ((ByteArray.empty.push 0x00) ++ txid)

def nodeHash (l r : Bytes) : Bytes :=
  SHA3.sha3_256 ((ByteArray.empty.push 0x01) ++ l ++ r)

def reduceLevel (xs : List Bytes) : List Bytes :=
  match xs with
  | [] => []
  | [x] => [x]
  | x :: y :: rest => nodeHash x y :: reduceLevel rest

def merkleRoot (txids : List Bytes) : Option Bytes :=
  match txids with
  | [] => none
  | _ =>
      let rec go (fuel : Nat) (level : List Bytes) : Option Bytes :=
        match fuel with
        | 0 => none
        | fuel + 1 =>
            match level with
            | [] => none
            | [r] => some r
            | _ => go fuel (reduceLevel level)
      go txids.length (txids.map leafHash)

end Merkle
end RubinFormal
