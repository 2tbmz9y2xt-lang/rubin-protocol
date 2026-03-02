import Std
import RubinFormal.Conformance.CVFlagdayVectors

namespace RubinFormal.Conformance

structure FlagdayResult where
  ok : Bool
  err : Option String
  activationHeight : Option Nat
  consensusActive : Option Bool
deriving Repr

def evalFlagdayVector (v : CVFlagdayVector) : FlagdayResult :=
  if v.name = "" then
    { ok := false
      err := some "featurebits: name required"
      activationHeight := none
      consensusActive := none
    }
  else if v.bit > 31 then
    { ok := false
      err := some s!"featurebits: bit out of range: {v.bit}"
      activationHeight := none
      consensusActive := none
    }
  else
    let active := v.height >= v.activationHeight
    { ok := true
      err := none
      activationHeight := some v.activationHeight
      consensusActive := some active
    }

def optEqFlagday {α : Type} [DecidableEq α] (exp : Option α) (act : Option α) : Bool :=
  match exp with
  | none => true
  | some e => act == some e

def checkFlagdayVector (v : CVFlagdayVector) : Bool :=
  let r := evalFlagdayVector v
  if v.expectOk then
    r.ok == true
      && optEqFlagday v.expectErr r.err
      && optEqFlagday v.expectActivationHeight r.activationHeight
      && optEqFlagday v.expectConsensusActive r.consensusActive
  else
    r.ok == false && optEqFlagday v.expectErr r.err

def allCVFlagday : Bool :=
  cvFlagdayVectors.all checkFlagdayVector

theorem cv_flagday_vectors_pass : allCVFlagday = true := by
  native_decide

end RubinFormal.Conformance
