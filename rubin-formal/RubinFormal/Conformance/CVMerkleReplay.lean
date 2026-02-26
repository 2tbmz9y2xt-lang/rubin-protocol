import Std
import RubinFormal.Conformance.CVMerkleVectors
import RubinFormal.Hex
import RubinFormal.MerkleV2

namespace RubinFormal.Conformance

open RubinFormal

private def decodeAllHex? (xs : List String) : Option (List Bytes) :=
  xs.mapM RubinFormal.decodeHex?

def checkMerkleVector (v : CVMerkleVector) : Bool :=
  let txids? := decodeAllHex? v.txidsHex
  let expRoot? := RubinFormal.decodeHexOpt? v.expectMerkleRootHex
  let expNot? := RubinFormal.decodeHexOpt? v.expectNotMerkleRootHex
  if v.expectOk then
    match txids?, expRoot? with
    | some txids, some expRoot =>
        match Merkle.merkleRoot txids with
        | some r =>
            let ok := r == expRoot
            let okNot :=
              match expNot? with
              | none => true
              | some nexp => r != nexp
            ok && okNot
        | none => false
    | _, _ => false
  else
    -- negative vectors are accepted only as "has an expected error label"
    v.expectMerkleRootHex.isNone

def allCVMerkle : Bool :=
  cvMerkleVectors.all checkMerkleVector

end RubinFormal.Conformance
