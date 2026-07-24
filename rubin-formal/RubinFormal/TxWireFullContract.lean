import RubinFormal.UtxoBasicV1
import RubinFormal.TxWirePrefixLemmas
import RubinFormal.TxWireCompactSizeLemmas
import Std.Tactic.Omega

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

def inputStructurallyWellFormed (i : TxIn) : Prop :=
  i.prevTxid.size = 32 ∧
  i.prevVout ≤ 0xffffffff ∧
  i.sequence ≤ 0xffffffff ∧
  i.scriptSig.size ≤ UInt64.size - 1

def outputStructurallyWellFormed (o : TxOut) : Prop :=
  o.value ≤ UInt64.size - 1 ∧
  o.covenantType ≤ 0xffff ∧
  o.covenantData.size ≤ UInt64.size - 1

def witnessItemStructurallyWellFormed (w : WitnessItem) : Prop :=
  w.suiteId ≤ 0xff ∧
  w.pubkey.size ≤ UInt64.size - 1 ∧
  w.signature.size ≤ UInt64.size - 1

def daCoreStructurallyWellFormed (txKind : Nat) (daCoreBytes : Bytes) : Prop :=
  ({ bs := daCoreBytes, off := 0 } : Cursor).remaining = daCoreBytes.size ∧
  ∃ c', DaCoreV1.parseDaCoreFields txKind { bs := daCoreBytes, off := 0 } = some c' ∧
    c'.off = daCoreBytes.size

def txStructurallyWellFormed (tx : Tx) : Prop :=
  tx.version ≤ 0xffffffff ∧
  (tx.txKind = 0x00 ∨ tx.txKind = 0x01 ∨ tx.txKind = 0x02) ∧
  tx.txNonce ≤ UInt64.size - 1 ∧
  (∀ i, i ∈ tx.inputs → inputStructurallyWellFormed i) ∧
  tx.inputs.length ≤ UInt64.size - 1 ∧
  (∀ o, o ∈ tx.outputs → outputStructurallyWellFormed o) ∧
  tx.outputs.length ≤ UInt64.size - 1 ∧
  tx.locktime ≤ 0xffffffff ∧
  daCoreStructurallyWellFormed tx.txKind tx.daCoreBytes ∧
  (∀ w, w ∈ tx.witness → witnessItemStructurallyWellFormed w) ∧
  tx.witness.length ≤ UInt64.size - 1 ∧
  tx.daPayloadLen = tx.daPayload.size ∧
  tx.daPayloadLen ≤ UInt64.size - 1 ∧
  (tx.txKind ≠ 0x00 ∨ tx.daPayloadLen = 0)

private theorem wire_u16le_size (n : Nat) : (RubinFormal.WireEnc.u16le n).size = 2 := rfl

private theorem wire_u32le_size (n : Nat) : (RubinFormal.WireEnc.u32le n).size = 4 := rfl

private theorem wire_u64le_size (n : Nat) : (RubinFormal.WireEnc.u64le n).size = 8 := rfl

private theorem bytes_append_empty (bs : Bytes) : bs = bs ++ ByteArray.empty := by
  cases bs
  rename_i data
  ext <;> simp [ByteArray.append, ByteArray.empty, Array.append_assoc]

theorem parseInput_serializeInput
    (i : TxIn)
    (h : inputStructurallyWellFormed i) :
    parseInput { bs := serializeInput i, off := 0 } =
      some (i, { bs := serializeInput i, off := (serializeInput i).size }) := by
  rcases h with ⟨hTxid, hVout, hSeq, hSig⟩
  unfold parseInput
  unfold serializeInput
  rw [show
      i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
        RubinFormal.WireEnc.compactSize i.scriptSig.size ++ i.scriptSig ++
        RubinFormal.WireEnc.u32le i.sequence =
      i.prevTxid ++
        (RubinFormal.WireEnc.u32le i.prevVout ++
          (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
            (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))) by
        simp [cursor_bytes_left_assoc]]
  rw [cursor_getBytes_prefix_exact
    (pre := i.prevTxid)
      (rest := RubinFormal.WireEnc.u32le i.prevVout ++
        (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence)))
      (n := 32) hTxid]
  simp
  have hU32 :
      Cursor.getU32le?
        {
          bs :=
            i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
          off := 32
        } =
        some
          (i.prevVout,
            {
              bs :=
                i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
              off := 32 + 4
            }) := by
    simpa [hTxid, Nat.add_assoc, cursor_bytes_left_assoc, RubinFormal.WireEnc.u32le] using
      (cursor_getU32le_after_pre
        (pre := i.prevTxid)
        (rest := RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))
        (n := i.prevVout) hVout)
  have hU32Size : (RubinFormal.WireEnc.u32le i.prevVout).size = 4 := by
    simpa using wire_u32le_size i.prevVout
  have hCompact :
      Cursor.getCompactSize?
        {
          bs :=
            i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
          off := 32 + 4
        } =
        some
          (i.scriptSig.size,
            {
              bs :=
                i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
              off := 32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size
            },
            true) := by
    have hBsCompact :
        i.prevTxid ++
          (RubinFormal.WireEnc.u32le i.prevVout ++
            (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
              (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))) =
        (i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout) ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence) := by
      simp [cursor_bytes_left_assoc]
    have hPreSize : (i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout).size = 32 + 4 := by
      rw [ByteArray.size_append, hTxid, hU32Size]
    simpa [hBsCompact, hPreSize, Nat.add_assoc] using
      (cursor_getCompactSize_after_pre
        (pre := i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout)
        (rest := i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence)
        (n := i.scriptSig.size) hSig)
  have hBytes :
      Cursor.getBytes?
        {
          bs :=
            i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
          off := 32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size
        }
        i.scriptSig.size =
        some
          (i.scriptSig,
            {
              bs :=
                i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
              off := 32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size + i.scriptSig.size
            }) := by
    have hBsBytes :
        i.prevTxid ++
          (RubinFormal.WireEnc.u32le i.prevVout ++
            (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
              (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))) =
        (i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size) ++
          i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence := by
      simp [cursor_bytes_left_assoc]
    have hPreSize :
        (i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size).size =
        32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size := by
      rw [ByteArray.size_append, ByteArray.size_append, hTxid, hU32Size]
    simpa [hBsBytes, hPreSize, Nat.add_assoc] using
      (cursor_getBytes_after_pre_exact
        (pre := i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size)
        (mid := i.scriptSig)
        (post := RubinFormal.WireEnc.u32le i.sequence)
        (n := i.scriptSig.size)
        rfl)
  have hSeqRead :
      Cursor.getU32le?
        {
          bs :=
            i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
          off := 32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size + i.scriptSig.size
        } =
        some
          (i.sequence,
            {
              bs :=
                i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
              off := 32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size + i.scriptSig.size + 4
            }) := by
    have hBsSeq :
        i.prevTxid ++
          (RubinFormal.WireEnc.u32le i.prevVout ++
            (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
              (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))) =
        (i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size ++ i.scriptSig) ++
          RubinFormal.WireEnc.u32le i.sequence ++ ByteArray.empty := by
      calc
        i.prevTxid ++
            (RubinFormal.WireEnc.u32le i.prevVout ++
              (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))) =
          (i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
            RubinFormal.WireEnc.compactSize i.scriptSig.size ++ i.scriptSig) ++
            RubinFormal.WireEnc.u32le i.sequence := by
              simp [cursor_bytes_left_assoc]
        _ =
          (i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
            RubinFormal.WireEnc.compactSize i.scriptSig.size ++ i.scriptSig) ++
            RubinFormal.WireEnc.u32le i.sequence ++ ByteArray.empty := by
              simpa using
                bytes_append_empty
                  ((i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
                    RubinFormal.WireEnc.compactSize i.scriptSig.size ++ i.scriptSig) ++
                    RubinFormal.WireEnc.u32le i.sequence)
    have hPreSeqSize :
        (i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size ++ i.scriptSig).size =
        32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size + i.scriptSig.size := by
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, hTxid, hU32Size]
    simpa [hBsSeq, hPreSeqSize, Nat.add_assoc] using
      (cursor_getU32le_after_pre
        (pre := i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size ++ i.scriptSig)
        (rest := ByteArray.empty)
        (n := i.sequence) hSeq)
  refine ⟨(i.prevVout,
    {
      bs :=
        i.prevTxid ++
          (RubinFormal.WireEnc.u32le i.prevVout ++
            (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
              (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
      off := 32 + 4
    }), hU32, ?_⟩
  refine ⟨(i.scriptSig.size,
    {
      bs :=
        i.prevTxid ++
          (RubinFormal.WireEnc.u32le i.prevVout ++
            (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
              (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
      off := 32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size
    },
    true), hCompact, ?_⟩
  constructor
  · refine ⟨(), by simp [requireMinimal]⟩
  · refine ⟨(i.scriptSig,
      {
        bs :=
          i.prevTxid ++
            (RubinFormal.WireEnc.u32le i.prevVout ++
              (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
        off := 32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size + i.scriptSig.size
      }), hBytes, ?_⟩
    refine ⟨(i.sequence,
      {
        bs :=
          i.prevTxid ++
            (RubinFormal.WireEnc.u32le i.prevVout ++
              (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence))),
        off := 32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size + i.scriptSig.size + 4
      }), hSeqRead, ?_⟩
    constructor
    · rfl
    · have hSeqSize : (RubinFormal.WireEnc.u32le i.sequence).size = 4 := by
        simpa using wire_u32le_size i.sequence
      have hSerializeInputSize :
          (serializeInput i).size =
            32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size + i.scriptSig.size + 4 := by
        rw [show serializeInput i =
            i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
              RubinFormal.WireEnc.compactSize i.scriptSig.size ++ i.scriptSig ++
              RubinFormal.WireEnc.u32le i.sequence by rfl]
        rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, ByteArray.size_append,
          hTxid, hU32Size, hSeqSize]
      have hSerializeInputExpandedSize :
          ByteArray.size
            (i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence)))) =
            32 + 4 + (RubinFormal.WireEnc.compactSize i.scriptSig.size).size + i.scriptSig.size + 4 := by
        simpa [serializeInput, cursor_bytes_left_assoc] using hSerializeInputSize
      rw [hSerializeInputExpandedSize]

theorem parseOutput_serializeOutput
    (o : TxOut)
    (h : outputStructurallyWellFormed o) :
    parseOutput { bs := serializeOutput o, off := 0 } =
      some (o, { bs := serializeOutput o, off := (serializeOutput o).size }) := by
  rcases h with ⟨hValue, hType, hData⟩
  unfold parseOutput
  unfold serializeOutput
  rw [show
      RubinFormal.WireEnc.u64le o.value ++ RubinFormal.WireEnc.u16le o.covenantType ++
        RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData =
      RubinFormal.WireEnc.u64le o.value ++
        (RubinFormal.WireEnc.u16le o.covenantType ++
          (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)) by
        simp [cursor_bytes_left_assoc]]
  rw [cursor_getU64le_prefix
    (n := o.value)
    (rest := RubinFormal.WireEnc.u16le o.covenantType ++
      (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData))
    hValue]
  simp
  have hTypeBytes :
      Cursor.getBytes?
        {
          bs :=
            RubinFormal.WireEnc.u64le o.value ++
              (RubinFormal.WireEnc.u16le o.covenantType ++
                (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
          off := 8
        }
        2 =
        some
          (RubinFormal.WireEnc.u16le o.covenantType,
            {
              bs :=
                RubinFormal.WireEnc.u64le o.value ++
                  (RubinFormal.WireEnc.u16le o.covenantType ++
                    (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
              off := 8 + 2
            }) := by
    simpa [Nat.add_assoc, cursor_bytes_left_assoc, RubinFormal.WireEnc.u64le] using
      (cursor_getBytes_after_pre_exact
        (pre := RubinFormal.WireEnc.u64le o.value)
        (mid := RubinFormal.WireEnc.u16le o.covenantType)
        (post := RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)
        (n := 2)
        (by rfl))
  have hU64Size : (RubinFormal.WireEnc.u64le o.value).size = 8 := by
    simpa using wire_u64le_size o.value
  have hU16Size : (RubinFormal.WireEnc.u16le o.covenantType).size = 2 := by
    simpa using wire_u16le_size o.covenantType
  have hValueNat : (UInt64.ofNat o.value).toNat = o.value := by
    have hLt : o.value < UInt64.size := by
      exact Nat.lt_of_le_of_lt hValue (by decide)
    simp [UInt64.ofNat, UInt64.toNat, Fin.ofNat, Nat.mod_eq_of_lt hLt]
  have hTypeRoundtrip :
      Wire.u16le?
        (ByteArray.get! (RubinFormal.WireEnc.u16le o.covenantType) 0)
        (ByteArray.get! (RubinFormal.WireEnc.u16le o.covenantType) 1) = o.covenantType := by
    simpa [RubinFormal.WireEnc.u16le] using u16le_ofNat_roundtrip o.covenantType hType
  have hCompact :
      Cursor.getCompactSize?
        {
          bs :=
            RubinFormal.WireEnc.u64le o.value ++
              (RubinFormal.WireEnc.u16le o.covenantType ++
                (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
          off := 8 + 2
        } =
        some
          (o.covenantData.size,
            {
              bs :=
                RubinFormal.WireEnc.u64le o.value ++
                  (RubinFormal.WireEnc.u16le o.covenantType ++
                    (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
              off := 8 + 2 + (RubinFormal.WireEnc.compactSize o.covenantData.size).size
            },
            true) := by
    have hBsCompact :
        RubinFormal.WireEnc.u64le o.value ++
          (RubinFormal.WireEnc.u16le o.covenantType ++
            (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)) =
        (RubinFormal.WireEnc.u64le o.value ++ RubinFormal.WireEnc.u16le o.covenantType) ++
          RubinFormal.WireEnc.compactSize o.covenantData.size ++
          o.covenantData := by
      simp [cursor_bytes_left_assoc]
    have hPreSize : (RubinFormal.WireEnc.u64le o.value ++ RubinFormal.WireEnc.u16le o.covenantType).size = 8 + 2 := by
      rw [ByteArray.size_append, hU64Size, hU16Size]
    simpa [hBsCompact, hPreSize, Nat.add_assoc] using
      (cursor_getCompactSize_after_pre
        (pre := RubinFormal.WireEnc.u64le o.value ++ RubinFormal.WireEnc.u16le o.covenantType)
        (rest := o.covenantData)
        (n := o.covenantData.size) hData)
  have hDataBytes :
      Cursor.getBytes?
        {
          bs :=
            RubinFormal.WireEnc.u64le o.value ++
              (RubinFormal.WireEnc.u16le o.covenantType ++
                (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
          off := 8 + 2 + (RubinFormal.WireEnc.compactSize o.covenantData.size).size
        }
        o.covenantData.size =
        some
          (o.covenantData,
            {
              bs :=
                RubinFormal.WireEnc.u64le o.value ++
                  (RubinFormal.WireEnc.u16le o.covenantType ++
                    (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
              off := 8 + 2 + (RubinFormal.WireEnc.compactSize o.covenantData.size).size + o.covenantData.size
            }) := by
    have hBsBytes :
        RubinFormal.WireEnc.u64le o.value ++
          (RubinFormal.WireEnc.u16le o.covenantType ++
            (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)) =
        RubinFormal.WireEnc.u64le o.value ++
          (RubinFormal.WireEnc.u16le o.covenantType ++
            (RubinFormal.WireEnc.compactSize o.covenantData.size ++
              (o.covenantData ++ ByteArray.empty))) := by
      simpa using
        congrArg
          (fun tail =>
            RubinFormal.WireEnc.u64le o.value ++
              (RubinFormal.WireEnc.u16le o.covenantType ++
                (RubinFormal.WireEnc.compactSize o.covenantData.size ++ tail)))
          (bytes_append_empty o.covenantData)
    have hPreSize :
        (RubinFormal.WireEnc.u64le o.value ++ RubinFormal.WireEnc.u16le o.covenantType ++
          RubinFormal.WireEnc.compactSize o.covenantData.size).size =
        8 + 2 + (RubinFormal.WireEnc.compactSize o.covenantData.size).size := by
      rw [ByteArray.size_append, ByteArray.size_append, hU64Size, hU16Size]
    rw [hBsBytes]
    have hRaw :=
      (cursor_getBytes_after_pre_exact
        (pre := RubinFormal.WireEnc.u64le o.value ++ RubinFormal.WireEnc.u16le o.covenantType ++
          RubinFormal.WireEnc.compactSize o.covenantData.size)
        (mid := o.covenantData)
        (post := ByteArray.empty)
        (n := o.covenantData.size)
        rfl)
    have hBsFlat :
        RubinFormal.WireEnc.u64le o.value ++
          (RubinFormal.WireEnc.u16le o.covenantType ++
            (RubinFormal.WireEnc.compactSize o.covenantData.size ++
              (o.covenantData ++ ByteArray.empty))) =
        (RubinFormal.WireEnc.u64le o.value ++ RubinFormal.WireEnc.u16le o.covenantType ++
          RubinFormal.WireEnc.compactSize o.covenantData.size) ++
          o.covenantData ++ ByteArray.empty := by
      simp [cursor_bytes_left_assoc, cursor_bytes_append_assoc]
    rw [hPreSize] at hRaw
    rw [hBsFlat]
    exact hRaw
  refine ⟨(RubinFormal.WireEnc.u16le o.covenantType,
    {
      bs :=
        RubinFormal.WireEnc.u64le o.value ++
          (RubinFormal.WireEnc.u16le o.covenantType ++
            (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
      off := 8 + 2
    }), hTypeBytes, ?_⟩
  refine ⟨(o.covenantData.size,
    {
      bs :=
        RubinFormal.WireEnc.u64le o.value ++
          (RubinFormal.WireEnc.u16le o.covenantType ++
            (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
      off := 8 + 2 + (RubinFormal.WireEnc.compactSize o.covenantData.size).size
    },
    true), hCompact, ?_⟩
  constructor
  · refine ⟨(), by simp [requireMinimal]⟩
  · refine ⟨(o.covenantData,
      {
        bs :=
          RubinFormal.WireEnc.u64le o.value ++
            (RubinFormal.WireEnc.u16le o.covenantType ++
              (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData)),
        off := 8 + 2 + (RubinFormal.WireEnc.compactSize o.covenantData.size).size + o.covenantData.size
      }), hDataBytes, ?_⟩
    constructor
    · cases o
      simpa using And.intro hValueNat hTypeRoundtrip
    · have hSerializeOutputSize :
          (serializeOutput o).size =
            8 + 2 + (RubinFormal.WireEnc.compactSize o.covenantData.size).size + o.covenantData.size := by
        rw [show serializeOutput o =
            RubinFormal.WireEnc.u64le o.value ++ RubinFormal.WireEnc.u16le o.covenantType ++
              RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData by rfl]
        rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, hU64Size, hU16Size]
      have hSerializeOutputExpandedSize :
          ByteArray.size
            (RubinFormal.WireEnc.u64le o.value ++
              (RubinFormal.WireEnc.u16le o.covenantType ++
                (RubinFormal.WireEnc.compactSize o.covenantData.size ++ o.covenantData))) =
            8 + 2 + (RubinFormal.WireEnc.compactSize o.covenantData.size).size + o.covenantData.size := by
        simpa [serializeOutput, cursor_bytes_left_assoc] using hSerializeOutputSize
      rw [hSerializeOutputExpandedSize]

end UtxoBasicV1

end RubinFormal
