import RubinFormal.SubsidyV1
import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVSubsidyVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.SubsidyV1
open RubinFormal.UtxoBasicV1

private def zeroChainIdSubsidy : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsSubsidy? (us : List CVSubsidyUtxo) : Option (List (Outpoint × UtxoEntry)) :=
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

def evalSubsidy (v : CVSubsidyVector) : (Bool × Option String) :=
  match RubinFormal.decodeHex? v.blockHex with
  | none => (false, some "TX_ERR_PARSE")
  | some blockBytes =>
      let ph := RubinFormal.decodeHexOpt? v.expectedPrevHashHex
      let tgt := RubinFormal.decodeHexOpt? v.expectedTargetHex
      match v.op with
      | .connect_block_basic =>
          match toUtxoPairsSubsidy? v.utxos with
          | none => (false, some "TX_ERR_PARSE")
          | some utxos =>
              match SubsidyV1.connectBlockBasic blockBytes ph tgt v.height v.alreadyGenerated utxos zeroChainIdSubsidy with
              | .ok _ => (true, none)
              | .error e => (false, some e)
      | .block_basic_check_with_fees =>
          match v.sumFees with
          | none => (false, some "TX_ERR_PARSE")
          | some sf =>
              match SubsidyV1.blockBasicCheckWithFees blockBytes ph tgt v.height v.alreadyGenerated sf with
              | .ok _ => (true, none)
              | .error e => (false, some e)

def subsidyVectorPass (v : CVSubsidyVector) : Bool :=
  let (ok, err) := evalSubsidy v
  if v.expectOk then
    ok
  else
    (!ok) && (err == v.expectErr)

def cvSubsidyVectorsPass : Bool :=
  cvSubsidyVectors.all subsidyVectorPass

theorem cv_subsidy_vectors_pass : cvSubsidyVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
