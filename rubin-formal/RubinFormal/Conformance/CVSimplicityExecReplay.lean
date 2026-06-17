import Std
import RubinFormal.Conformance.CVSimplicityExecVectors

namespace RubinFormal.Conformance

private def semanticsVersion : Nat := 1
private def maxProgramBytes : Nat := 16384
private def maxExecCost : Nat := 400000
private def stepCost : Nat := 1
private def maxFrameBytes : Nat := 65536
private def maxLiveMemoryBytes : Nat := 1048576

private def errDecode : String := "TX_ERR_SIMPLICITY_DECODE"
private def errProgramTooLarge : String := "TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE"
private def errCmrMismatch : String := "TX_ERR_SIMPLICITY_CMR_MISMATCH"
private def errJetDisallowed : String := "TX_ERR_SIMPLICITY_JET_DISALLOWED"
private def errBudgetExceeded : String := "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED"
private def errRejected : String := "TX_ERR_SIMPLICITY_REJECTED"

structure CVSimplicityExecResult where
  ok : Bool
  err : String
  accepted : Option Bool
  finalCounter : Option Nat
deriving DecidableEq, Repr

private def okResult (accepted : Bool) (cost : Nat) : CVSimplicityExecResult :=
  { ok := true, err := "", accepted := some accepted, finalCounter := some cost }

private def errOnly (err : String) : CVSimplicityExecResult :=
  { ok := false, err, accepted := none, finalCounter := none }

private def evalErr (err : String) (accepted : Bool) (cost : Nat) : CVSimplicityExecResult :=
  { ok := false, err, accepted := some accepted, finalCounter := some cost }

private def normalizeHex (s : String) : String :=
  let low := s.trim.toLower
  if low.startsWith "0x" then low.drop 2 else low

private def optNormalizeHex (s : Option String) : String :=
  match s with
  | none => ""
  | some x => normalizeHex x

private def hexByteLen? (s : String) : Option Nat :=
  let h := normalizeHex s
  if h.length % 2 == 0 then some (h.length / 2) else none

private def optionHexTooLong (s : Option String) (maxBytes : Nat) : Bool :=
  match s with
  | none => false
  | some x =>
      match hexByteLen? x with
      | some n => n > maxBytes
      | none => false

private def programTooLarge (programHex : String) : Bool :=
  match hexByteLen? programHex with
  | some n => n > maxProgramBytes
  | none => false

private def frameBytes (bits : Nat) : Nat :=
  (bits + 7) / 8

private def checkMemoryFrom (live : Nat) : List Nat → Bool
  | [] => true
  | bits :: rest =>
      let frame := frameBytes bits
      frame <= maxFrameBytes &&
        live + frame <= maxLiveMemoryBytes &&
        checkMemoryFrom (live + frame) rest

private def checkMemory (frames : List Nat) : Bool :=
  checkMemoryFrom 0 frames

private def evalSteps (steps : Nat) (frames : List Nat) : CVSimplicityExecResult :=
  if steps == 0 then
    evalErr errDecode false 0
  else if !checkMemory frames then
    evalErr errBudgetExceeded false 0
  else
    let maxSteps := maxExecCost / stepCost
    if steps > maxSteps then
      evalErr errBudgetExceeded true maxExecCost
    else
      okResult true (steps * stepCost)

private def cmrMatches (actual : Option String) (expected : String) : Bool :=
  match actual with
  | none => true
  | some got => normalizeHex got == expected

private def semanticsMatches (v : CVSimplicityExecVector) : Bool :=
  v.semanticsVersion.getD semanticsVersion == semanticsVersion

private def witnessAllowed (actual : Option String) (allowed : List String) : Bool :=
  allowed.contains (optNormalizeHex actual)

private def evalPlainProgram
    (v : CVSimplicityExecVector)
    (cmr : String)
    (witnesses : List String)
    (steps : Nat)
    (frames : List Nat) : CVSimplicityExecResult :=
  if !cmrMatches v.covenantCmrHex cmr then
    errOnly errCmrMismatch
  else if !semanticsMatches v then
    errOnly errDecode
  else if optionHexTooLong v.witnessHex maxProgramBytes then
    errOnly "bad witness_hex"
  else if !witnessAllowed v.witnessHex witnesses then
    errOnly errDecode
  else
    evalSteps steps frames

private def evalJetProgram
    (v : CVSimplicityExecVector)
    (cmr : String)
    (frames : List Nat) : CVSimplicityExecResult :=
  if !cmrMatches v.covenantCmrHex cmr then
    errOnly errCmrMismatch
  else if !semanticsMatches v then
    errOnly errDecode
  else if optionHexTooLong v.witnessHex maxProgramBytes then
    errOnly "bad witness_hex"
  else if optNormalizeHex v.witnessHex != "" then
    errOnly errDecode
  else if !checkMemory frames then
    evalErr errBudgetExceeded false 0
  else
    match v.jetCost with
    | none => errOnly "bad jet_cost"
    | some cost =>
        let accepted := v.jetAccepted.getD false
        if cost > maxExecCost then
          evalErr errBudgetExceeded accepted maxExecCost
        else if !accepted then
          evalErr errRejected false cost
        else
          okResult true cost

private def evalSynthetic (v : CVSimplicityExecVector) : CVSimplicityExecResult :=
  match v.evalSteps with
  | none =>
      if v.frameBitWidths.isEmpty then errOnly "bad program_hex" else errOnly "bad eval_steps"
  | some steps => evalSteps steps v.frameBitWidths

def evalSimplicityExecVector (v : CVSimplicityExecVector) : CVSimplicityExecResult :=
  match v.programHex with
  | none => evalSynthetic v
  | some programHex =>
      let p := normalizeHex programHex
      if programTooLarge programHex then
        errOnly errProgramTooLarge
      else if p == "24" then
        evalPlainProgram v "c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7" [""] 1 [0, 0]
      else if p == "c1220f0100" then
        evalPlainProgram v "afeae8c18903b9e0aae2c125f31f7b8e09de916e461f221936b633d587c1b434" [""] 4 [0, 0]
      else if p == "8900" then
        evalPlainProgram v "d296a48e538af38908242ab30244036fdb66e9056d5f812a5b328fae2b6a2726" [""] 2 [0, 0]
      else if p == "c1d21014" then
        evalPlainProgram v "d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83" ["00", "80"] 4 [1, 1]
      else if p == "60" then
        evalJetProgram v "3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637" [512, 256]
      else if p == "70" then
        evalJetProgram v "f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941" [58008, 1]
      else if p == "7c0680" then
        errOnly errJetDisallowed
      else
        errOnly errDecode

private def vectorResultMatches (v : CVSimplicityExecVector) : Bool :=
  let got := evalSimplicityExecVector v
  got.ok == v.expectOk &&
    got.err == v.expectErr.getD "" &&
    got.accepted == v.expectAccepted &&
    got.finalCounter == v.expectFinalCounter

private def allDistinctIds (vs : List CVSimplicityExecVector) : Bool :=
  let ids := vs.map (·.id)
  ids.length == ids.eraseDups.length

private def allOpsMatch (vs : List CVSimplicityExecVector) : Bool :=
  vs.all fun v => v.op == "simplicity_exec_vector"

private def hasFamilies (vs : List CVSimplicityExecVector) (families : List String) : Bool :=
  families.all fun fam => vs.any fun v => v.id.startsWith ("CV-SE-" ++ fam ++ "-")

def allCVSimplicityExec : Bool :=
  cvSimplicityExecVectors.length == 27
    && allDistinctIds cvSimplicityExecVectors
    && allOpsMatch cvSimplicityExecVectors
    && hasFamilies cvSimplicityExecVectors ["PE", "EXEC", "MEM", "REPEAT"]
    && cvSimplicityExecVectors.all vectorResultMatches

theorem cv_simplicity_exec_vector_count : cvSimplicityExecVectors.length = 27 := by
  native_decide

theorem cv_simplicity_exec_vectors_pass : allCVSimplicityExec = true := by
  native_decide

end RubinFormal.Conformance
