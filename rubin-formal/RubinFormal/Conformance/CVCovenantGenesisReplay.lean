import RubinFormal.UtxoBasicV1
import RubinFormal.CovenantGenesisV1
import RubinFormal.Conformance.CVCovenantGenesisVectors
import RubinFormal.Hex

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
  match RubinFormal.decodeHex? v.txHex with
  | none => false
  | some tx =>
      match covenantGenesisEval tx with
      | .ok _ => v.expectOk
      | .error e => (!v.expectOk) && (some e == v.expectErr)

def cvCovenantGenesisVectorsPass : Bool :=
  cvCovenantGenesisVectors.all covenantGenesisVectorPass

end RubinFormal.Conformance
