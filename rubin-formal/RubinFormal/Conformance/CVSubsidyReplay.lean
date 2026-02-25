import RubinFormal.SubsidyV1
import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVSubsidyVectors

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.SubsidyV1

def toUtxoPairs (us : List CVSubsidyUtxo) : List (UtxoBasicV1.Outpoint × UtxoBasicV1.UtxoEntry) :=
  us.map (fun u =>
    (
      { txid := u.txid, vout := u.vout },
      {
        value := u.value,
        covenantType := u.covenantType,
        covenantData := u.covenantData,
        creationHeight := u.creationHeight,
        createdByCoinbase := u.createdByCoinbase
      }
    )
  )

def evalSubsidy (v : CVSubsidyVector) : (Bool × Option String) :=
  let chainId : Bytes := ByteArray.mk (List.replicate 32 0)
  match v.op with
  | .connect_block_basic =>
      match SubsidyV1.connectBlockBasic v.block v.expectedPrevHash v.expectedTarget v.height v.alreadyGenerated (toUtxoPairs v.utxos) chainId with
      | .ok _ => (true, none)
      | .error e => (false, some e)
  | .block_basic_check_with_fees =>
      match v.sumFees with
      | none => (false, some "TX_ERR_PARSE")
      | some sf =>
          match SubsidyV1.blockBasicCheckWithFees v.block v.expectedPrevHash v.expectedTarget v.height v.alreadyGenerated sf with
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
