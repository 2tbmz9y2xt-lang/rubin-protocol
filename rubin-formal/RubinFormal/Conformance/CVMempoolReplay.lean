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

-- CORE_SIMPLICITY pre-activation policy rows (Go RUB-527 / Rust RUB-528):
-- the pinned reject is a node-policy outcome, not floor arithmetic. The
-- replay proves (a) the row pins exactly the policy reject shape
-- (ok, admit=false, admit_class "rejected", no floor reject_reason) and
-- (b) the shared floor arithmetic over the pinned numbers is ACCEPTING —
-- i.e. the pre-activation guardrail, not a fee floor, rejects the
-- transaction. The reject reason strings themselves are proven
-- byte-identical Go↔Rust by the executable conformance runner.
def simplicityPreActivePolicyErr (err : Option String) : Bool :=
  err == some "CORE_SIMPLICITY output pre-ACTIVE"
    || err == some "CORE_SIMPLICITY spend pre-ACTIVE"

def mempoolSimplicityPolicyVectorPass (v : CVMempoolVector) : Bool :=
  let d := cvMempoolToDaFeeFloorVector v
  let got := evalDaFeeFloor d
  v.expectOk
    && !v.expectAdmit
    && v.expectAdmitClass == "rejected"
    && v.expectRejectReason == none
    && got.admit
    && got.rejectReason == none
    && got.dominantFloor == v.expectDominantFloor
    && v.expectRelayFeeFloor == got.relayFeeFloor
    && v.expectDaFeeFloor == got.daFeeFloor
    && v.expectDaSurcharge == got.daSurcharge
    && v.expectDaRequiredFee == got.daRequiredFee
    && v.expectRequiredFee == got.requiredFee

def mempoolVectorPass (v : CVMempoolVector) : Bool :=
  if simplicityPreActivePolicyErr v.expectErr then
    mempoolSimplicityPolicyVectorPass v
  else
    daFeeFloorVectorPass (cvMempoolToDaFeeFloorVector v)

def cvMempoolVectorsPass : Bool :=
  cvMempoolVectors.all mempoolVectorPass

theorem cv_mempool_vectors_pass : cvMempoolVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
