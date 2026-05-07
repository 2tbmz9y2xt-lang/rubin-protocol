import RubinFormal.Conformance.CVMempoolVectors
import RubinFormal.Conformance.CVDaFeeFloorReplay

namespace RubinFormal.Conformance

-- CV-MEMPOOL bounded pass intentionally uses the existing da_fee_floor_policy
-- replay surface. Capacity/source vectors require a later replay op.
def cvMempoolToDaFeeFloorVector (v : CVMempoolVector) : CVDaFeeFloorVector := {
  id := v.id,
  txHex := v.txHex,
  expectOk := v.expectOk,
  expectErr := v.expectErr,
  fee := v.fee,
  weight := v.weight,
  daBytes := v.daBytes,
  currentMempoolMinFeeRate := v.currentMempoolMinFeeRate,
  minDaFeeRate := v.minDaFeeRate,
  daSurchargePerByte := v.daSurchargePerByte,
  expectAdmit := v.expectAdmit,
  expectAdmitClass := v.expectAdmitClass,
  expectDominantFloor := v.expectDominantFloor,
  expectRejectReason := v.expectRejectReason,
  expectRelayFeeFloor := v.expectRelayFeeFloor,
  expectDaFeeFloor := v.expectDaFeeFloor,
  expectDaSurcharge := v.expectDaSurcharge,
  expectDaRequiredFee := v.expectDaRequiredFee,
  expectRequiredFee := v.expectRequiredFee
}

def mempoolVectorPass (v : CVMempoolVector) : Bool :=
  daFeeFloorVectorPass (cvMempoolToDaFeeFloorVector v)

def cvMempoolVectorsPass : Bool :=
  cvMempoolVectors.all mempoolVectorPass

theorem cv_mempool_vectors_pass : cvMempoolVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
