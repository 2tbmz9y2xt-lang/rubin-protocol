import RubinFormal.SubsidyV1
import RubinFormal.Conformance.CVDevnetSubsidyVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.SubsidyV1

private def zeroChainIdDevnetSubsidy : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

-- NOTE:
-- `conformance/devnetcv/devnetcv.go` mines the subsidy samples via `MineOne(..., nil)`,
-- so each `CV-DEVNET-SUBSIDY` block is coinbase-only. `SubsidyV1.connectBlockBasic`
-- only consults the UTXO set when validating non-coinbase txs, so an empty set is
-- sufficient here and keeps the generated Lean module tractable.
def evalDevnetSubsidy (v : CVDevnetSubsidyVector) : (Bool × Option String) :=
  match RubinFormal.decodeHex? v.blockHex with
  | none => (false, some "TX_ERR_PARSE")
  | some blockBytes =>
      let ph := RubinFormal.decodeHexOpt? v.expectedPrevHashHex
      let tgt := RubinFormal.decodeHexOpt? v.expectedTargetHex
      match v.op with
      | .connect_block_basic =>
          match SubsidyV1.connectBlockBasic blockBytes ph tgt v.height v.alreadyGenerated [] zeroChainIdDevnetSubsidy with
          | .ok _ => (true, none)
          | .error e => (false, some e)
      | .block_basic_check_with_fees =>
          match v.sumFees with
          | none => (false, some "TX_ERR_PARSE")
          | some sf =>
              match SubsidyV1.blockBasicCheckWithFees blockBytes ph tgt v.height v.alreadyGenerated sf with
              | .ok _ => (true, none)
              | .error e => (false, some e)

def devnetSubsidyVectorPass (v : CVDevnetSubsidyVector) : Bool :=
  let (ok, err) := evalDevnetSubsidy v
  if v.expectOk then
    ok
  else
    (!ok) && (err == v.expectErr)

def cvDevnetSubsidyVectorsPass : Bool :=
  cvDevnetSubsidyVectors.all devnetSubsidyVectorPass

-- native_decide is both stronger (proof-level) and faster than #eval
-- (1.8s native vs SIGTERM at 19min interpreted on CI runners)
theorem cv_devnet_subsidy_vectors_pass : cvDevnetSubsidyVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
