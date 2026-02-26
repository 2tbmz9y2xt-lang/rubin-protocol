import Std
import RubinFormal.Conformance.CVDeterminismVectors

namespace RubinFormal.Conformance

def keyBytes (s : String) : List UInt8 :=
  let low := s.trim.toLower
  if low.startsWith "0x" then
    let hex := low.drop 2
    -- interpret as raw hex bytes; assume even length (fixtures are well-formed)
    let chars := hex.toList
    let toNib (c : Char) : Nat :=
      if '0' ≤ c && c ≤ '9' then c.toNat - '0'.toNat
      else if 'a' ≤ c && c ≤ 'f' then 10 + (c.toNat - 'a'.toNat)
      else 0
    let rec go (cs : List Char) (acc : List UInt8) : List UInt8 :=
      match cs with
      | a :: b :: rest =>
        let v := (toNib a) * 16 + (toNib b)
        go rest (acc ++ [UInt8.ofNat v])
      | _ => acc
    go chars []
  else
    s.toUTF8.data.toList

def lexLT (a b : List UInt8) : Bool :=
  match a, b with
  | [], [] => false
  | [], _ => true
  | _, [] => false
  | x::xs, y::ys =>
    if x < y then true
    else if x > y then false
    else lexLT xs ys

def insertBy (lt : α → α → Bool) (x : α) : List α → List α
  | [] => [x]
  | y :: ys =>
      if lt x y then
        x :: y :: ys
      else
        y :: insertBy lt x ys

def sortBy (lt : α → α → Bool) : List α → List α
  | [] => []
  | x :: xs => insertBy lt x (sortBy lt xs)

def stableSortKeys (keys : List String) : List String :=
  sortBy (fun a b => lexLT (keyBytes a) (keyBytes b)) keys

def checkDeterminismVector (v : CVDeterminismVector) : Bool :=
  let got := stableSortKeys v.keys
  (got == v.expectSortedKeys) && v.expectOk

def allCVDeterminism : Bool :=
  cvDeterminismVectors.all checkDeterminismVector

end RubinFormal.Conformance
