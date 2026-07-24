import RubinFormal.BlockValidationOrder
import RubinFormal.ConnectBlockStrong
namespace RubinFormal
open BlockBasicV1 UtxoBasicV1

/-!
# Determinism Requirements

In Lean 4, all functions are pure — `f x = f x` is trivially true
by reflexivity and does not need a theorem. The real determinism
requirement is cross-implementation: Go and Rust must produce
identical results for identical inputs. This is verified by:
1. Conformance vectors (CV-* fixtures)
2. Go-trace refinement replay (GoTraceV1Check.lean)
3. Sighash replay (CVSighashReplay.lean)

This file proves non-trivial determinism properties that go beyond
pure-function reflexivity.
-/

/-- validateBlockBasic result determines accept/reject for any input. -/
theorem validateBlockBasic_total
    (blockBytes : Bytes) (ph pt : Option Bytes) :
    section25AcceptWitness blockBytes ph pt ∨
    (∃ err, validateBlockBasic blockBytes ph pt = .error err) :=
  validateBlockBasic_accept_or_reject blockBytes ph pt

/-- connectBlockTxs over empty tx list is identity on UTXO map. -/
theorem connectBlockTxs_empty_identity
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) :
    SubsidyV1.connectBlockTxs [] utxoMap h bt cid = .ok (0, utxoMap) := by rfl

end RubinFormal
