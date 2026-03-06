import RubinFormal.SubsidyV1
import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVDevnetGenesisVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.SubsidyV1
open RubinFormal.UtxoBasicV1

private def zeroChainIdDevnetGenesis : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsDevnetGenesis? (us : List CVDevnetGenesisUtxo) : Option (List (Outpoint × UtxoEntry)) :=
  us.mapM (fun u => do
    let txid <- RubinFormal.decodeHex? u.txidHex
    let cd <- RubinFormal.decodeHex? u.covenantDataHex
    pure
      (
        { txid := txid, vout := u.vout },
        {
          value := u.value
          covenantType := u.covenantType
          covenantData := cd
          creationHeight := u.creationHeight
          createdByCoinbase := u.createdByCoinbase
        }
      ))

def devnetGenesisVectorPass (v : CVDevnetGenesisVector) : Bool :=
  match RubinFormal.decodeHex? v.blockHex, toUtxoPairsDevnetGenesis? v.utxos with
  | some blockBytes, some utxos =>
      let ph := RubinFormal.decodeHexOpt? v.expectedPrevHashHex
      let tgt := RubinFormal.decodeHexOpt? v.expectedTargetHex
      match SubsidyV1.connectBlockBasic blockBytes ph tgt v.height v.alreadyGenerated utxos zeroChainIdDevnetGenesis with
      | .ok _ => v.expectOk
      | .error e =>
          if v.expectOk then
            false
          else
            v.expectErr == some e
  | _, _ => false

def cvDevnetGenesisVectorsPass : Bool :=
  cvDevnetGenesisVectors.all devnetGenesisVectorPass

#eval
  if cvDevnetGenesisVectorsPass then
    ()
  else
    panic! "[FAIL] CV-DEVNET-GENESIS replay: cvDevnetGenesisVectorsPass=false"

theorem cv_devnet_genesis_vectors_pass : cvDevnetGenesisVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
