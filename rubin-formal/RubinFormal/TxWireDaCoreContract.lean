import RubinFormal.TxWireDaCoreBase
import RubinFormal.TxWireDaCoreKind1Contract
import RubinFormal.TxWireDaCoreKind2Contract

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem parseDaCoreFieldsWithBytes_between
    (txKind : Nat)
    (pre : Bytes)
    (daCoreBytes : Bytes)
    (post : Bytes)
    (hKind : txKind = 0x00 ∨ txKind = 0x01 ∨ txKind = 0x02)
    (h : daCoreStructurallyWellFormed txKind daCoreBytes) :
    DaCoreV1.parseDaCoreFieldsWithBytes txKind
      { bs := pre ++ daCoreBytes ++ post, off := pre.size } =
      some ({ bs := pre ++ daCoreBytes ++ post, off := pre.size + daCoreBytes.size }, daCoreBytes.size) := by
  rcases hKind with rfl | hKind1 | hKind2
  · exact parseDaCoreFieldsWithBytes_kind0_between pre daCoreBytes post h
  · rcases hKind1 with rfl
    exact parseDaCoreFieldsWithBytes_kind1_between pre daCoreBytes post h
  · rcases hKind2 with rfl
    exact parseDaCoreFieldsWithBytes_kind2_between pre daCoreBytes post h

end UtxoBasicV1

end RubinFormal
