import RubinFormal.Refinement.GoTraceV1Check

def main : IO Unit := do
  if RubinFormal.Refinement.allGoTraceV1Ok then
    IO.println "[OK] Go trace v1 refinement"
  else
    let hint :=
      match RubinFormal.Refinement.firstGoTraceV1Mismatch with
      | none => "(unknown mismatch)"
      | some s => s
    throw (IO.userError ("[FAIL] Go trace v1 refinement mismatch at " ++ hint))
