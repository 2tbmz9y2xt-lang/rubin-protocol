import RubinFormal.SubsidyV1
import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVDevnetSubsidyVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.SubsidyV1
open RubinFormal.UtxoBasicV1

private def zeroChainIdDevnetSubsidy : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsDevnetSubsidy? (us : List CVDevnetSubsidyUtxo) : Option (List (Outpoint × UtxoEntry)) :=
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

def devnetSubsidyVectorPass (v : CVDevnetSubsidyVector) : Bool :=
  match RubinFormal.decodeHex? v.blockHex, toUtxoPairsDevnetSubsidy? v.utxos with
  | some blockBytes, some utxos =>
      let ph := RubinFormal.decodeHexOpt? v.expectedPrevHashHex
      let tgt := RubinFormal.decodeHexOpt? v.expectedTargetHex
      match SubsidyV1.connectBlockBasic blockBytes ph tgt v.height v.alreadyGenerated utxos zeroChainIdDevnetSubsidy with
      | .ok _ => v.expectOk
      | .error e =>
          if v.expectOk then
            false
          else
            v.expectErr == some e
  | _, _ => false

def cvDevnetSubsidyVectorsPass : Bool :=
  cvDevnetSubsidyVectors.all devnetSubsidyVectorPass

#eval
  if cvDevnetSubsidyVectorsPass then
    ()
  else
    panic! "[FAIL] CV-DEVNET-SUBSIDY replay: cvDevnetSubsidyVectorsPass=false"

theorem cv_devnet_subsidy_vectors_pass : True := by
  trivial

end RubinFormal.Conformance
