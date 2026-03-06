import RubinFormal.SubsidyV1
import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVDevnetChainVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.SubsidyV1
open RubinFormal.UtxoBasicV1

private def zeroChainIdDevnetChain : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsDevnetChain? (us : List CVDevnetChainUtxo) : Option (List (Outpoint × UtxoEntry)) :=
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

def devnetChainVectorPass (v : CVDevnetChainVector) : Bool :=
  match RubinFormal.decodeHex? v.blockHex, toUtxoPairsDevnetChain? v.utxos with
  | some blockBytes, some utxos =>
      let ph := RubinFormal.decodeHexOpt? v.expectedPrevHashHex
      let tgt := RubinFormal.decodeHexOpt? v.expectedTargetHex
      match SubsidyV1.connectBlockBasic blockBytes ph tgt v.height v.alreadyGenerated utxos zeroChainIdDevnetChain with
      | .ok _ => v.expectOk
      | .error e =>
          if v.expectOk then
            false
          else
            v.expectErr == some e
  | _, _ => false

def cvDevnetChainVectorsPass : Bool :=
  cvDevnetChainVectors.all devnetChainVectorPass

-- native_decide: proof-level verification, faster than #eval on CI
theorem cv_devnet_chain_vectors_pass : cvDevnetChainVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
