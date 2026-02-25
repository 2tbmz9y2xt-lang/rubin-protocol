import Std
import RubinFormal.Conformance.CVMerkleVectors
import RubinFormal.MerkleV2

namespace RubinFormal.Conformance

open RubinFormal

def checkMerkleVector (v : CVMerkleVector) : Bool :=
  if !v.expectOk then
    false
  else
    match Merkle.merkleRoot v.txids, v.expectMerkleRoot with
    | some r, some exp =>
      let ok := (r == exp)
      let okNot :=
        match v.expectNotMerkleRoot with
        | none => true
        | some nexp => r != nexp
      ok && okNot
    | _, _ => false

def allCVMerkle : Bool :=
  cvMerkleVectors.all checkMerkleVector

theorem cv_merkle_vectors_pass : allCVMerkle = true := by
  native_decide

end RubinFormal.Conformance

