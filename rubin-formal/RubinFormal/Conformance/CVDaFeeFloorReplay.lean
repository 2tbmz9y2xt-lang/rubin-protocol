import RubinFormal.Conformance.CVDaFeeFloorVectors

namespace RubinFormal.Conformance

def maxU64 : Nat := 18446744073709551615

def defaultMempoolMinFeeRate : Nat := 1

def defaultMinDaFeeRate : Nat := 1

def checkedMul? (a b : Nat) : Option Nat :=
  let p := a * b
  if p <= maxU64 then some p else none

def checkedAdd? (a b : Nat) : Option Nat :=
  let s := a + b
  if s <= maxU64 then some s else none

def floorMax (a b : Nat) : Nat :=
  if a > b then a else b

def dominantFeeFloor (relayFeeFloor daRequiredFee : Nat) : String :=
  if daRequiredFee > relayFeeFloor then
    "da"
  else if relayFeeFloor > daRequiredFee then
    "relay"
  else if relayFeeFloor == 0 then
    "none"
  else
    "tie"

def feeBelowRollingFloor (fee weight floor : Nat) : Bool :=
  if weight == 0 then
    true
  else
    let f := floorMax floor defaultMempoolMinFeeRate
    fee < weight * f

structure EvalOut where
  admit : Bool
  admitClass : String
  dominantFloor : String
  rejectReason : Option String
  relayFeeFloor : Option Nat
  daFeeFloor : Option Nat
  daSurcharge : Option Nat
  daRequiredFee : Option Nat
  requiredFee : Option Nat
  deriving BEq

def evalDaFeeFloor (v : CVDaFeeFloorVector) : EvalOut :=
  let minFeeRate := floorMax v.currentMempoolMinFeeRate defaultMempoolMinFeeRate
  let minDaFeeRate := if v.minDaFeeRate == 0 then defaultMinDaFeeRate else v.minDaFeeRate
  let relayFloor? := checkedMul? v.weight minFeeRate
  let relayDominant :=
    match relayFloor? with
    | some rf => dominantFeeFloor rf 0
    | none => "relay"
  let acceptedBase : EvalOut := {
    admit := false,
    admitClass := "accepted",
    dominantFloor := relayDominant,
    rejectReason := none,
    relayFeeFloor := relayFloor?,
    daFeeFloor := some 0,
    daSurcharge := some 0,
    daRequiredFee := some 0,
    requiredFee := relayFloor?
  }
  let afterDa? : Option EvalOut :=
    if v.daBytes == 0 then
      some acceptedBase
    else
      match checkedMul? v.daBytes minDaFeeRate with
      | none => some { acceptedBase with admitClass := "rejected", dominantFloor := "da", rejectReason := some "DA_FEE_FLOOR_OVERFLOW" }
      | some daFloor =>
          match checkedMul? v.daBytes v.daSurchargePerByte with
          | none => some { acceptedBase with admitClass := "rejected", dominantFloor := "da", rejectReason := some "DA_SURCHARGE_OVERFLOW", daFeeFloor := some daFloor }
          | some daSurcharge =>
              match checkedAdd? daFloor daSurcharge with
              | none => some { acceptedBase with admitClass := "rejected", dominantFloor := "da", rejectReason := some "DA_REQUIRED_FEE_OVERFLOW", daFeeFloor := some daFloor, daSurcharge := some daSurcharge }
              | some daRequired =>
                  let withDa := { acceptedBase with daFeeFloor := some daFloor, daSurcharge := some daSurcharge, daRequiredFee := some daRequired }
                  if daRequired > 0 && v.fee < daRequired then
                    some { withDa with admitClass := "rejected", dominantFloor := "da", rejectReason := some "DA_FEE_BELOW_STAGE_C_FLOOR", requiredFee := some daRequired }
                  else
                    let required? := relayFloor?.map (fun rf => floorMax rf daRequired)
                    let dom :=
                      match relayFloor? with
                      | some rf => dominantFeeFloor rf daRequired
                      | none => "relay"
                    some { withDa with requiredFee := required?, dominantFloor := dom }
  match afterDa? with
  | none => acceptedBase
  | some out =>
      if out.rejectReason.isSome then
        out
      else if feeBelowRollingFloor v.fee v.weight minFeeRate then
        { out with admitClass := "unavailable", dominantFloor := "relay", rejectReason := some "MEMPOOL_FEE_BELOW_ROLLING_MINIMUM", requiredFee := relayFloor? }
      else
        { out with admit := true }

def daFeeFloorVectorPass (v : CVDaFeeFloorVector) : Bool :=
  let got := evalDaFeeFloor v
  let expectNatMatches (expected actual : Option Nat) : Bool :=
    match expected with
    | none => true
    | some n => actual.getD 0 == n
  got.admit == v.expectAdmit
    && got.admitClass == v.expectAdmitClass
    && got.dominantFloor == v.expectDominantFloor
    && got.rejectReason == v.expectRejectReason
    && expectNatMatches v.expectRelayFeeFloor got.relayFeeFloor
    && expectNatMatches v.expectDaFeeFloor got.daFeeFloor
    && expectNatMatches v.expectDaSurcharge got.daSurcharge
    && expectNatMatches v.expectDaRequiredFee got.daRequiredFee
    && expectNatMatches v.expectRequiredFee got.requiredFee

def cvDaFeeFloorVectorsPass : Bool :=
  cvDaFeeFloorVectors.all daFeeFloorVectorPass

theorem cv_da_fee_floor_vectors_pass : cvDaFeeFloorVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
