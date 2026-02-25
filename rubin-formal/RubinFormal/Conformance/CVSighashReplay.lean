import RubinFormal.SighashV1
import RubinFormal.Conformance.CVSighashVectors

namespace RubinFormal.Conformance

open RubinFormal.SighashV1

def evalSighash (v : CVSighashVector) : (Bool × Option String × Option Bytes) :=
  match SighashV1.digestV1 v.tx v.chainId v.inputIndex v.inputValue with
  | .ok d => (true, none, some d)
  | .error e => (false, some e, none)

def sighashVectorPass (v : CVSighashVector) : Bool :=
  let (ok, _err, out) := evalSighash v
  ok && (out == some v.expectDigest)

def cvSighashVectorsPass : Bool :=
  cvSighashVectors.all sighashVectorPass

theorem cv_sighash_vectors_pass : cvSighashVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

