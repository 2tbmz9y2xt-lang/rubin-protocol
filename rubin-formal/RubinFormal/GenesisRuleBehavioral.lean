import RubinFormal.CovenantGenesisV1
namespace RubinFormal
open CovenantGenesisV1

/-- P2PK, ANCHOR, HTLC covenant types are pairwise distinct at genesis. -/
theorem genesis_covenant_types_distinct :
    COV_TYPE_P2PK ≠ COV_TYPE_ANCHOR ∧
    COV_TYPE_P2PK ≠ COV_TYPE_HTLC ∧
    COV_TYPE_ANCHOR ≠ COV_TYPE_HTLC := by native_decide

/-- P2PK tag is strictly less than HTLC tag (ordering invariant). -/
theorem genesis_p2pk_before_htlc : COV_TYPE_P2PK < COV_TYPE_HTLC := by native_decide

/-- ANCHOR tag is strictly less than HTLC tag. -/
theorem genesis_anchor_before_htlc : COV_TYPE_ANCHOR < COV_TYPE_HTLC := by native_decide

end RubinFormal
