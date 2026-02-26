import Lake
open Lake DSL

package «rubin-formal» where

require std from git
  "https://github.com/leanprover/std4" @ "v4.6.0"

lean_lib RubinFormal where

lean_exe rubin_conformance where
  root := `RubinFormal.Conformance.Main
