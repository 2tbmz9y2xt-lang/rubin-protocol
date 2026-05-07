import RubinFormal.Conformance.CVMempoolVectors
import RubinFormal.Conformance.CVDaFeeFloorReplay

namespace RubinFormal.Conformance

-- CV-MEMPOOL vectors share the DA/rolling-floor arithmetic replay here.
-- `mempool_relay_metadata_policy` rows additionally prove the actual
-- Go/Rust relay metadata entrypoints in the executable conformance runner;
-- capacity/source vectors still require a later replay op.
def cvMempoolToDaFeeFloorVector (v : CVMempoolVector) : CVDaFeeFloorVector := {
  id := v.id,
  op := v.op,
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
