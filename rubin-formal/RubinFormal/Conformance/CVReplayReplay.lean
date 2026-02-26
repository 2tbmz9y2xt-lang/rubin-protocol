import RubinFormal.BlockBasicCheckV1
import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVReplayVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.BlockBasicCheckV1

def insertNat (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys =>
      if x ≤ y then
        x :: y :: ys
      else
        y :: insertNat x ys

def sortNat : List Nat → List Nat
  | [] => []
  | x :: xs => insertNat x (sortNat xs)

def findDuplicates (xs : List Nat) : List Nat :=
  let rec go (rest : List Nat) (seen : List Nat) (dups : List Nat) : List Nat :=
    match rest with
    | [] => dups
    | x :: rs =>
        if seen.contains x then
          if dups.contains x then
            go rs seen dups
          else
            go rs seen (dups ++ [x])
        else
          go rs (seen ++ [x]) dups
  go xs [] []

def checkReplayVector (v : CVReplayVector) : Bool :=
  if v.op == "nonce_replay_intrablock" then
    let dups := sortNat (findDuplicates v.nonces)
    let exp := sortNat v.expectDuplicates
    let ok := dups == exp && (v.expectOk == (dups.isEmpty))
    match v.expectErr with
    | none => ok
    | some e => ok && (if dups.isEmpty then false else e == "TX_ERR_NONCE_REPLAY")
  else if v.op == "block_basic_check" then
    match v.blockHex, v.expectedPrevHashHex, v.expectedTargetHex with
    | some bHex, some phHex, some tgtHex =>
        match RubinFormal.decodeHex? bHex, RubinFormal.decodeHex? phHex, RubinFormal.decodeHex? tgtHex with
        | some b, some ph, some tgt =>
            match BlockBasicCheckV1.validateBlockBasicCheck b (some ph) (some tgt) RubinFormal.UtxoBasicV1.SLH_DSA_ACTIVATION_HEIGHT v.prevTimestamps with
            | .ok _ => v.expectOk
            | .error e => (!v.expectOk) && (some e == v.expectErr)
        | _, _, _ => false
    | _, _, _ => false
  else
    false

def allCVReplay : Bool :=
  cvReplayVectors.all checkReplayVector

end RubinFormal.Conformance
