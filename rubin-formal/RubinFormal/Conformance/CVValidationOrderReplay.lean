import RubinFormal.Conformance.CVValidationOrderVectors

namespace RubinFormal.Conformance

def evalOrder (checks : List ValidationCheck) : (Option String) × (List String) :=
  let rec go (rest : List ValidationCheck) (evaluated : List String) : (Option String) × (List String) :=
    match rest with
    | [] => (none, evaluated)
    | c :: cs =>
      let evaluated' := evaluated ++ [c.name]
      if c.fails then
        (some c.err, evaluated')
      else
        go cs evaluated'
  go checks []

def checkValidationOrderVector (v : CVValidationOrderVector) : Bool :=
  let (firstErr, evaluated) := evalOrder v.checks
  let ok := firstErr.isNone
  (ok == v.expectOk) &&
  (firstErr == v.expectFirstErr) &&
  (evaluated == v.expectEvaluated)

def allCVValidationOrder : Bool :=
  cvValidationOrderVectors.all checkValidationOrderVector

end RubinFormal.Conformance
