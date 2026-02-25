import RubinFormal.UtxoBasicV1
import RubinFormal.CovenantGenesisV1
import RubinFormal.Conformance.CVCovenantGenesisVectors

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.UtxoBasicV1
open RubinFormal.CovenantGenesisV1

def covenantGenesisEval (txBytes : Bytes) : Except String Unit := do
  let tx ← UtxoBasicV1.parseTx txBytes
  for o in tx.outputs do
    CovenantGenesisV1.validateOutGenesis
      { value := o.value, covenantType := o.covenantType, covenantData := o.covenantData }
      tx.txKind 0
  pure ()

def covenantGenesisVectorPass (v : CVCovenantGenesisVector) : Bool :=
  match covenantGenesisEval v.tx with
  | .ok _ => v.expectOk
  | .error e => (!v.expectOk) && (some e == v.expectErr)

def cvCovenantGenesisVectorsPass : Bool :=
  cvCovenantGenesisVectors.all covenantGenesisVectorPass

theorem cv_covenant_genesis_vectors_pass : cvCovenantGenesisVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

