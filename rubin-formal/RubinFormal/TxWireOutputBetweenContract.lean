import RubinFormal.TxWireOutputPostContract

set_option maxHeartbeats 1000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem wire_u16le_size (n : Nat) : (RubinFormal.WireEnc.u16le n).size = 2 := rfl

private theorem wire_u64le_size (n : Nat) : (RubinFormal.WireEnc.u64le n).size = 8 := rfl

private theorem cursor_getCompactSize_after_prefix_exact
    (pre rest : Bytes)
    (n : Nat)
    (hN : n ≤ UInt64.size - 1) :
    Cursor.getCompactSize?
      {
        bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
        off := pre.size
      } =
      some
        (n,
          {
            bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
            off := pre.size + (RubinFormal.WireEnc.compactSize n).size
          },
          true) := by
  simpa [cursor_bytes_left_assoc, Nat.add_assoc] using
    (cursor_getCompactSize_after_pre
      (pre := pre)
      (rest := rest)
      (n := n)
      hN)

private theorem cursor_getBytes_after_prefix_exact'
    (pre mid post : Bytes) :
    Cursor.getBytes?
      {
        bs := pre ++ mid ++ post,
        off := pre.size
      }
      mid.size =
      some
        (mid,
          {
            bs := pre ++ mid ++ post,
            off := pre.size + mid.size
          }) := by
  simpa [cursor_bytes_left_assoc, Nat.add_assoc] using
    (cursor_getBytes_after_pre_exact
      (pre := pre)
      (mid := mid)
      (post := post)
      (n := mid.size)
      rfl)

theorem parseOutput_serializeOutput_between
    (pre : Bytes)
    (o : TxOut)
    (post : Bytes)
    (h : outputStructurallyWellFormed o) :
    parseOutput { bs := pre ++ serializeOutput o ++ post, off := pre.size } =
      some
        (o,
          {
            bs := pre ++ serializeOutput o ++ post,
            off := pre.size + (serializeOutput o).size
          }) := by
  rcases h with ⟨hValue, hType, hData⟩
  have hValueNat : (UInt64.ofNat o.value).toNat = o.value := by
    have hLt : o.value < UInt64.size := by
      exact Nat.lt_of_le_of_lt hValue (by decide)
    simp [UInt64.ofNat, UInt64.toNat, Fin.ofNat, Nat.mod_eq_of_lt hLt]
  have hU64Size : (RubinFormal.WireEnc.u64le o.value).size = 8 := by
    simpa using wire_u64le_size o.value
  have hU16Size : (RubinFormal.WireEnc.u16le o.covenantType).size = 2 := by
    simpa using wire_u16le_size o.covenantType
  have hTypeRoundtrip :
      Wire.u16le?
        (ByteArray.get! (RubinFormal.WireEnc.u16le o.covenantType) 0)
        (ByteArray.get! (RubinFormal.WireEnc.u16le o.covenantType) 1) = o.covenantType := by
    simpa [RubinFormal.WireEnc.u16le] using u16le_ofNat_roundtrip o.covenantType hType
  let valueBytes : Bytes := RubinFormal.WireEnc.u64le o.value
  let typeBytes : Bytes := RubinFormal.WireEnc.u16le o.covenantType
  let dataCompact : Bytes := RubinFormal.WireEnc.compactSize o.covenantData.size
  let afterValue : Bytes := typeBytes ++ dataCompact ++ o.covenantData ++ post
  let afterType : Bytes := dataCompact ++ o.covenantData ++ post
  let bs : Bytes := pre ++ valueBytes ++ typeBytes ++ dataCompact ++ o.covenantData ++ post
  unfold parseOutput
  unfold serializeOutput
  have hU64 :
      Cursor.getU64le? { bs := bs, off := pre.size } =
        some
          (UInt64.ofNat o.value,
            {
              bs := bs,
              off := pre.size + 8
            }) := by
    simpa [bs, valueBytes, typeBytes, dataCompact, afterValue, afterType, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getU64le_after_pre
        (pre := pre)
        (rest := afterValue)
        (n := o.value)
        hValue)
  have hU64Exp :
      Cursor.getU64le?
        {
          bs :=
            pre ++
                (RubinFormal.WireEnc.u64le o.value ++
                  RubinFormal.WireEnc.u16le o.covenantType ++
                  RubinFormal.WireEnc.compactSize o.covenantData.size ++
                  o.covenantData) ++
              post,
          off := pre.size
        } =
      some
        (UInt64.ofNat o.value,
          {
            bs :=
              pre ++
                  (RubinFormal.WireEnc.u64le o.value ++
                    RubinFormal.WireEnc.u16le o.covenantType ++
                    RubinFormal.WireEnc.compactSize o.covenantData.size ++
                    o.covenantData) ++
                post,
            off := pre.size + 8
          }) := by
    simpa [bs, valueBytes, typeBytes, dataCompact, afterValue, afterType, cursor_bytes_left_assoc] using hU64
  rw [hU64Exp]
  simp [hValueNat]
  let typePre : Bytes := pre ++ valueBytes
  have hTypePreSize : typePre.size = pre.size + 8 := by
    rw [ByteArray.size_append, hU64Size]
  have hTypeBytes :
      Cursor.getBytes? { bs := bs, off := pre.size + 8 } 2 =
        some
          (RubinFormal.WireEnc.u16le o.covenantType,
            { bs := bs, off := pre.size + 8 + 2 }) := by
    rw [show bs = typePre ++ typeBytes ++ afterType by
      simp [bs, typePre, valueBytes, typeBytes, dataCompact, afterType, cursor_bytes_left_assoc]]
    rw [← hTypePreSize]
    simpa [typePre, valueBytes, typeBytes, dataCompact, afterType, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_prefix_exact'
        (pre := typePre)
        (mid := typeBytes)
        (post := afterType))
  let dataPre : Bytes := typePre ++ typeBytes
  have hDataPreSize : dataPre.size = pre.size + 8 + 2 := by
    rw [ByteArray.size_append, hTypePreSize, hU16Size]
  have hCompact :
      Cursor.getCompactSize? { bs := bs, off := pre.size + 8 + 2 } =
        some
          (o.covenantData.size,
            { bs := bs, off := pre.size + 8 + 2 + dataCompact.size },
            true) := by
    rw [show bs = dataPre ++ dataCompact ++ (o.covenantData ++ post) by
      simp [bs, dataPre, typePre, valueBytes, typeBytes, dataCompact, cursor_bytes_left_assoc]]
    rw [← hDataPreSize]
    simpa [dataPre, typePre, valueBytes, typeBytes, dataCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getCompactSize_after_prefix_exact
        (pre := dataPre)
        (rest := o.covenantData ++ post)
        (n := o.covenantData.size)
        hData)
  let payloadPre : Bytes := dataPre ++ dataCompact
  have hPayloadPreSize : payloadPre.size = pre.size + 8 + 2 + dataCompact.size := by
    rw [ByteArray.size_append, hDataPreSize]
  have hDataBytes :
      Cursor.getBytes? { bs := bs, off := pre.size + 8 + 2 + dataCompact.size } o.covenantData.size =
        some
          (o.covenantData,
            { bs := bs, off := pre.size + 8 + 2 + dataCompact.size + o.covenantData.size }) := by
    rw [show bs = payloadPre ++ o.covenantData ++ post by
      simp [bs, payloadPre, dataPre, typePre, valueBytes, typeBytes, dataCompact, cursor_bytes_left_assoc]]
    rw [← hPayloadPreSize]
    simpa [payloadPre, dataPre, typePre, valueBytes, typeBytes, dataCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_prefix_exact'
        (pre := payloadPre)
        (mid := o.covenantData)
        (post := post))
  have hSerializeOutputSize :
      (serializeOutput o).size =
        8 + 2 + dataCompact.size + o.covenantData.size := by
    simp [serializeOutput, valueBytes, typeBytes, dataCompact, hU64Size, hU16Size,
      ByteArray.size_append, Nat.add_assoc]
  have hSerializeOutputExpandedSize :
      ByteArray.size
        (RubinFormal.WireEnc.u64le o.value ++
          RubinFormal.WireEnc.u16le o.covenantType ++
          RubinFormal.WireEnc.compactSize o.covenantData.size ++
          o.covenantData) =
        8 + 2 + dataCompact.size + o.covenantData.size := by
    simpa [serializeOutput, valueBytes, typeBytes, dataCompact, cursor_bytes_left_assoc] using
      hSerializeOutputSize
  have hTypeBytesExp :
      Cursor.getBytes?
          {
            bs :=
              pre ++
                  (RubinFormal.WireEnc.u64le o.value ++
                    RubinFormal.WireEnc.u16le o.covenantType ++
                    RubinFormal.WireEnc.compactSize o.covenantData.size ++
                    o.covenantData) ++
                post,
            off := pre.size + 8
          }
          2 =
        some
          (RubinFormal.WireEnc.u16le o.covenantType,
            {
              bs :=
                pre ++
                    (RubinFormal.WireEnc.u64le o.value ++
                      RubinFormal.WireEnc.u16le o.covenantType ++
                      RubinFormal.WireEnc.compactSize o.covenantData.size ++
                      o.covenantData) ++
                  post,
              off := pre.size + 8 + 2
            }) := by
    simpa [bs, valueBytes, typeBytes, dataCompact, afterValue, afterType, cursor_bytes_left_assoc] using hTypeBytes
  have hCompactExp :
      Cursor.getCompactSize?
          {
            bs :=
              pre ++
                  (RubinFormal.WireEnc.u64le o.value ++
                    RubinFormal.WireEnc.u16le o.covenantType ++
                    RubinFormal.WireEnc.compactSize o.covenantData.size ++
                    o.covenantData) ++
                post,
            off := pre.size + 8 + 2
          } =
        some
          (o.covenantData.size,
            {
              bs :=
                pre ++
                    (RubinFormal.WireEnc.u64le o.value ++
                      RubinFormal.WireEnc.u16le o.covenantType ++
                      RubinFormal.WireEnc.compactSize o.covenantData.size ++
                      o.covenantData) ++
                  post,
              off := pre.size + 8 + 2 + dataCompact.size
            },
            true) := by
    simpa [bs, valueBytes, typeBytes, dataCompact, afterValue, afterType, cursor_bytes_left_assoc] using hCompact
  have hDataBytesExp :
      Cursor.getBytes?
          {
            bs :=
              pre ++
                  (RubinFormal.WireEnc.u64le o.value ++
                    RubinFormal.WireEnc.u16le o.covenantType ++
                    RubinFormal.WireEnc.compactSize o.covenantData.size ++
                    o.covenantData) ++
                post,
            off := pre.size + 8 + 2 + dataCompact.size
          }
          o.covenantData.size =
        some
          (o.covenantData,
            {
              bs :=
                pre ++
                    (RubinFormal.WireEnc.u64le o.value ++
                      RubinFormal.WireEnc.u16le o.covenantType ++
                      RubinFormal.WireEnc.compactSize o.covenantData.size ++
                      o.covenantData) ++
                  post,
              off := pre.size + 8 + 2 + dataCompact.size + o.covenantData.size
            }) := by
    simpa [bs, valueBytes, typeBytes, dataCompact, afterValue, afterType, cursor_bytes_left_assoc] using hDataBytes
  rw [hTypeBytesExp]
  simp [hTypeRoundtrip]
  rw [hCompactExp]
  simp [requireMinimal]
  rw [hDataBytesExp]
  simp
  rw [hSerializeOutputExpandedSize]
  simpa [Nat.add_assoc]

end UtxoBasicV1

end RubinFormal
