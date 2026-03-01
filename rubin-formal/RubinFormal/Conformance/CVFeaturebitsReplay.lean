import Std
import RubinFormal.Conformance.CVFeaturebitsVectors

namespace RubinFormal.Conformance

def SIGNAL_WINDOW : Nat := 2016
def SIGNAL_THRESHOLD : Nat := 1815

inductive FeaturebitsState where
  | defined
  | started
  | lockedIn
  | active
  | failed
deriving DecidableEq, Repr

def FeaturebitsState.toString : FeaturebitsState → String
  | .defined => "DEFINED"
  | .started => "STARTED"
  | .lockedIn => "LOCKED_IN"
  | .active => "ACTIVE"
  | .failed => "FAILED"

def boundaryHeight (h : Nat) : Nat :=
  h - (h % SIGNAL_WINDOW)

def prevWindowSignalCount (b : Nat) (windowSignalCounts : List Nat) : Nat :=
  if b < SIGNAL_WINDOW then
    0
  else
    let idx := (b / SIGNAL_WINDOW) - 1
    windowSignalCounts.getD idx 0

def stateAtBoundaryIndex (idx : Nat) (startHeight timeoutHeight : Nat) (windowSignalCounts : List Nat) :
    FeaturebitsState :=
  match idx with
  | 0 =>
      if 0 >= startHeight then
        .started
      else
        .defined
  | Nat.succ n =>
      let prevState := stateAtBoundaryIndex n startHeight timeoutHeight windowSignalCounts
      let hb := (Nat.succ n) * SIGNAL_WINDOW
      match prevState with
      | .defined =>
          if hb >= startHeight then
            .started
          else
            .defined
      | .started =>
          let lockedIn := windowSignalCounts.getD n 0 >= SIGNAL_THRESHOLD
          let timedOut := hb >= timeoutHeight
          if lockedIn then
            .lockedIn
          else if timedOut then
            .failed
          else
            .started
      | .lockedIn =>
          .active
      | .active =>
          .active
      | .failed =>
          .failed

def stateAtBoundaryHeight (b : Nat) (startHeight timeoutHeight : Nat) (windowSignalCounts : List Nat) :
    FeaturebitsState :=
  stateAtBoundaryIndex (b / SIGNAL_WINDOW) startHeight timeoutHeight windowSignalCounts

structure FeaturebitsResult where
  ok : Bool
  err : Option String
  state : Option FeaturebitsState
  boundaryHeight : Option Nat
  prevWindowSignalCount : Option Nat
  signalWindow : Option Nat
  signalThreshold : Option Nat
  estimatedActivationHeight : Option Nat
deriving Repr

def evalFeaturebitsVector (v : CVFeaturebitsVector) : FeaturebitsResult :=
  if v.bit > 31 then
    { ok := false
      err := some s!"featurebits: bit out of range: {v.bit}"
      state := none
      boundaryHeight := none
      prevWindowSignalCount := none
      signalWindow := none
      signalThreshold := none
      estimatedActivationHeight := none
    }
  else
    let b := boundaryHeight v.height
    let st := stateAtBoundaryHeight b v.startHeight v.timeoutHeight v.windowSignalCounts
    let prev := prevWindowSignalCount b v.windowSignalCounts
    let est := if st == .lockedIn then some (b + SIGNAL_WINDOW) else none
    { ok := true
      err := none
      state := some st
      boundaryHeight := some b
      prevWindowSignalCount := some prev
      signalWindow := some SIGNAL_WINDOW
      signalThreshold := some SIGNAL_THRESHOLD
      estimatedActivationHeight := est
    }

def optEq {α : Type} [DecidableEq α] (exp : Option α) (act : Option α) : Bool :=
  match exp with
  | none => true
  | some e => act == some e

def checkFeaturebitsVector (v : CVFeaturebitsVector) : Bool :=
  let r := evalFeaturebitsVector v
  if v.expectOk then
    r.ok == true
      && optEq v.expectErr r.err
      && (match v.expectState, r.state with
          | none, _ => true
          | some es, some st => st.toString == es
          | some _, none => false)
      && optEq v.expectBoundaryHeight r.boundaryHeight
      && optEq v.expectPrevWindowSignalCount r.prevWindowSignalCount
      && optEq v.expectSignalWindow r.signalWindow
      && optEq v.expectSignalThreshold r.signalThreshold
      && optEq v.expectEstimatedActivationHeight r.estimatedActivationHeight
  else
    r.ok == false && optEq v.expectErr r.err

def allCVFeaturebits : Bool :=
  cvFeaturebitsVectors.all checkFeaturebitsVector

theorem cv_featurebits_vectors_pass : allCVFeaturebits = true := by
  native_decide

end RubinFormal.Conformance
