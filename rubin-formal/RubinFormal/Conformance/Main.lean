import RubinFormal.Conformance.Runner

def main : IO Unit := do
  let code ← RubinFormal.Conformance.run
  if code == 0 then
    pure ()
  else
    throw (IO.userError "rubin_conformance failed")

