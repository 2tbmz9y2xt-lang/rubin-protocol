import RubinFormal.Conformance.CVHtlcOrderingVectors

namespace RubinFormal.Conformance

def htlcOrderingEval (v : CVHtlcOrderingVector) : (Bool × Option String × Bool) :=
  let path := v.path.toLower
  let errPre : Option String :=
    if !v.structuralOk then
      some "TX_ERR_PARSE"
    else if path == "refund" && !v.locktimeOk then
      some "TX_ERR_TIMELOCK_NOT_MET"
    else if !(v.suiteId == 1 || v.suiteId == 2) then
      some "TX_ERR_SIG_ALG_INVALID"
    else if v.suiteId == 2 && v.blockHeight < v.slhActivationHeight then
      some "TX_ERR_SIG_ALG_INVALID"
    else if !v.keyBindingOk then
      some "TX_ERR_SIG_INVALID"
    else if path == "claim" && !v.preimageOk then
      some "TX_ERR_SIG_INVALID"
    else
      none

  let verifyCalled := errPre.isNone
  let err : Option String :=
    match errPre with
    | some e => some e
    | none =>
        if v.verifyOk then none else some "TX_ERR_SIG_INVALID"

  (err.isNone, err, verifyCalled)

def htlcOrderingVectorPass (v : CVHtlcOrderingVector) : Bool :=
  let (ok, err, verifyCalled) := htlcOrderingEval v
  let okPass := if v.expectOk then ok else (!ok && err == v.expectErr)
  okPass && (verifyCalled == v.expectVerifyCalled)

def cvHtlcOrderingVectorsPass : Bool :=
  cvHtlcOrderingVectors.all htlcOrderingVectorPass

theorem cv_htlc_ordering_vectors_pass : cvHtlcOrderingVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
