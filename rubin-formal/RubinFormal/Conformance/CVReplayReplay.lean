import RubinFormal.BlockBasicCheckV1
import RubinFormal.Conformance.CVReplayVectors

namespace RubinFormal.Conformance

open RubinFormal.BlockBasicCheckV1

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
    let dups := (findDuplicates v.nonces).qsort (· < ·)
    let exp := v.expectDuplicates.qsort (· < ·)
    let ok := dups == exp && (v.expectOk == (dups.isEmpty))
    match v.expectErr with
    | none => ok
    | some e => ok && (if dups.isEmpty then false else e == "TX_ERR_NONCE_REPLAY")
  else if v.op == "block_basic_check" then
    match v.block, v.expectedPrevHash, v.expectedTarget with
    | some b, some ph, some tgt =>
      match BlockBasicCheckV1.validateBlockBasicCheck b (some ph) (some tgt) v.prevTimestamps with
      | .ok _ => v.expectOk
      | .error e => (!v.expectOk) && (some e == v.expectErr)
    | _, _, _ => false
  else
    false

def allCVReplay : Bool :=
  cvReplayVectors.all checkReplayVector

theorem cv_replay_vectors_pass : allCVReplay = true := by
  native_decide

end RubinFormal.Conformance
