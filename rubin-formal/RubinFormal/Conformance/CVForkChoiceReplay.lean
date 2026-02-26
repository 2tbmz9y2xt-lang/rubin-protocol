import Std
import RubinFormal.Conformance.CVForkChoiceVectors

namespace RubinFormal.Conformance

def hexNib (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then some (10 + (c.toNat - 'a'.toNat))
  else if 'A' ≤ c && c ≤ 'F' then some (10 + (c.toNat - 'A'.toNat))
  else none

def parseHexNat (s : String) : Option Nat :=
  let t := s.trim
  let u := if t.startsWith "0x" || t.startsWith "0X" then t.drop 2 else t
  let rec go (cs : List Char) (acc : Nat) : Option Nat :=
    match cs with
    | [] => some acc
    | c :: rest =>
      match hexNib c with
      | none => none
      | some n => go rest (acc * 16 + n)
  go u.toList 0

def parseHexBytes (s : String) : Option (List UInt8) :=
  let t := s.trim
  let u := if t.startsWith "0x" || t.startsWith "0X" then t.drop 2 else t
  if u.length % 2 != 0 then
    none
  else
    let chars := u.toList
    let rec go (cs : List Char) (acc : List UInt8) : Option (List UInt8) :=
      match cs with
      | [] => some acc
      | a :: b :: rest =>
        match hexNib a, hexNib b with
        | some x, some y => go rest (acc ++ [UInt8.ofNat (x*16+y)])
        | _, _ => none
      | _ => none
    go chars []

def bytesLT (a b : List UInt8) : Bool :=
  match a, b with
  | [], [] => false
  | [], _ => true
  | _, [] => false
  | x::xs, y::ys =>
    if x < y then true else if x > y then false else bytesLT xs ys

def forkWork (target : Nat) : Nat :=
  ((Nat.shiftLeft 1 256) / target)

def checkForkWork (targetHex expectWorkHex : String) : Bool :=
  match parseHexNat targetHex, parseHexNat expectWorkHex with
  | some t, some exp =>
    if t == 0 then false
    else forkWork t == exp
  | _, _ => false

def chainTotalWork (targets : List String) : Option Nat :=
  targets.foldl
    (fun acc th =>
      match acc with
      | none => none
      | some total =>
          match parseHexNat th with
          | none => none
          | some t =>
              if t == 0 then none else some (total + forkWork t)
    )
    (some 0)

def selectWinner (chains : List ForkChain) : Option String := do
  let mut bestId : Option String := none
  let mut bestWork : Int := -1
  let mut bestTip : Option (List UInt8) := none
  for ch in chains do
    let w ← chainTotalWork ch.targets
    let tip ← parseHexBytes ch.tipHash
    let wI : Int := Int.ofNat w
    let better :=
      (wI > bestWork) ||
      (wI == bestWork && (match bestTip with | none => true | some bt => bytesLT tip bt))
    if better then
      bestWork := wI
      bestTip := some tip
      bestId := some ch.id
  bestId

def checkForkChoiceVector (v : CVForkChoiceVector) : Bool :=
  if v.op == "fork_work" then
    match v.target, v.expectWork with
    | some t, some exp =>
      v.expectOk && checkForkWork t exp
    | _, _ => false
  else if v.op == "fork_choice_select" then
    match v.expectWinner with
    | some w =>
      v.expectOk && (selectWinner v.chains == some w)
    | none => false
  else
    false

def allCVForkChoice : Bool :=
  cvForkChoiceVectors.all checkForkChoiceVector

theorem cv_fork_choice_vectors_pass : allCVForkChoice = true := by
  native_decide

end RubinFormal.Conformance
