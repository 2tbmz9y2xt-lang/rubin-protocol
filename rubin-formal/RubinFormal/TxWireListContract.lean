import RubinFormal.TxWireInputBetweenContract
import RubinFormal.TxWireOutputBetweenContract
import RubinFormal.TxWireWitnessBetweenContract

set_option maxHeartbeats 1000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem concatBytes_nil : concatBytes [] = ByteArray.empty := by
  rfl

private theorem concatBytes_cons (x : Bytes) (xs : List Bytes) :
    concatBytes (x :: xs) = x ++ concatBytes xs := by
  rfl

private theorem serializeInputs_cons (i : TxIn) (is : List TxIn) :
    serializeInputs (i :: is) = serializeInput i ++ serializeInputs is := by
  simp [serializeInputs, concatBytes_cons]

private theorem serializeOutputs_cons (o : TxOut) (os : List TxOut) :
    serializeOutputs (o :: os) = serializeOutput o ++ serializeOutputs os := by
  simp [serializeOutputs, concatBytes_cons]

private theorem serializeWitnessItems_cons (w : WitnessItem) (ws : List WitnessItem) :
    serializeWitnessItems (w :: ws) = serializeWitnessItem w ++ serializeWitnessItems ws := by
  simp [serializeWitnessItems, concatBytes_cons]

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

theorem parseInputs_serializeInputs_between
    (pre : Bytes)
    (ins : List TxIn)
    (post : Bytes)
    (h : ∀ i, i ∈ ins → inputStructurallyWellFormed i) :
    parseInputs { bs := pre ++ serializeInputs ins ++ post, off := pre.size } ins.length =
      some
        (ins,
          { bs := pre ++ serializeInputs ins ++ post, off := pre.size + (serializeInputs ins).size }) := by
  induction ins generalizing pre post with
  | nil =>
      simp [parseInputs, serializeInputs, concatBytes_nil]
  | cons i is ih =>
      have hi : inputStructurallyWellFormed i := h i (by simp)
      have htail : ∀ j, j ∈ is → inputStructurallyWellFormed j := by
        intro j hj
        exact h j (by simp [hj])
      rw [serializeInputs_cons]
      simp [parseInputs]
      have hHead :
          parseInput
            { bs := pre ++ serializeInput i ++ serializeInputs is ++ post, off := pre.size } =
          some
            (i,
              {
                bs := pre ++ serializeInput i ++ serializeInputs is ++ post,
                off := pre.size + (serializeInput i).size
              }) := by
        simpa [cursor_bytes_left_assoc] using
          (parseInput_serializeInput_between pre i (serializeInputs is ++ post) hi)
      refine ⟨(i,
          {
            bs := (pre ++ serializeInput i) ++ serializeInputs is ++ post,
            off := (pre ++ serializeInput i).size
          }),
        ?_, ?_⟩
      · simpa [cursor_bytes_left_assoc, ByteArray.size_append, Nat.add_assoc] using hHead
      · refine ⟨(is,
            {
              bs := (pre ++ serializeInput i) ++ serializeInputs is ++ post,
              off := (pre ++ serializeInput i).size + (serializeInputs is).size
            }),
          ?_, ?_⟩
        · exact ih (pre := pre ++ serializeInput i) (post := post) htail
        · constructor
          · constructor <;> rfl
          · simp [serializeInputs_cons, cursor_bytes_left_assoc, ByteArray.size_append, Nat.add_assoc]

theorem parseOutputs_serializeOutputs_between
    (pre : Bytes)
    (outs : List TxOut)
    (post : Bytes)
    (h : ∀ o, o ∈ outs → outputStructurallyWellFormed o) :
    parseOutputs { bs := pre ++ serializeOutputs outs ++ post, off := pre.size } outs.length =
      some
        (outs,
          { bs := pre ++ serializeOutputs outs ++ post, off := pre.size + (serializeOutputs outs).size }) := by
  induction outs generalizing pre post with
  | nil =>
      simp [parseOutputs, serializeOutputs, concatBytes_nil]
  | cons o os ih =>
      have ho : outputStructurallyWellFormed o := h o (by simp)
      have htail : ∀ x, x ∈ os → outputStructurallyWellFormed x := by
        intro x hx
        exact h x (by simp [hx])
      rw [serializeOutputs_cons]
      simp [parseOutputs]
      have hHead :
          parseOutput
            { bs := pre ++ serializeOutput o ++ serializeOutputs os ++ post, off := pre.size } =
          some
            (o,
              {
                bs := pre ++ serializeOutput o ++ serializeOutputs os ++ post,
                off := pre.size + (serializeOutput o).size
              }) := by
        simpa [cursor_bytes_left_assoc] using
          (parseOutput_serializeOutput_between pre o (serializeOutputs os ++ post) ho)
      refine ⟨(o,
          {
            bs := (pre ++ serializeOutput o) ++ serializeOutputs os ++ post,
            off := (pre ++ serializeOutput o).size
          }),
        ?_, ?_⟩
      · simpa [cursor_bytes_left_assoc, ByteArray.size_append, Nat.add_assoc] using hHead
      · refine ⟨(os,
            {
              bs := (pre ++ serializeOutput o) ++ serializeOutputs os ++ post,
              off := (pre ++ serializeOutput o).size + (serializeOutputs os).size
            }),
          ?_, ?_⟩
        · exact ih (pre := pre ++ serializeOutput o) (post := post) htail
        · constructor
          · constructor <;> rfl
          · simp [serializeOutputs_cons, cursor_bytes_left_assoc, ByteArray.size_append, Nat.add_assoc]

theorem parseWitnessItems_serializeWitnessItems_between
    (pre : Bytes)
    (wit : List WitnessItem)
    (post : Bytes)
    (h : ∀ w, w ∈ wit → witnessItemStructurallyWellFormed' w) :
    parseWitnessItems { bs := pre ++ serializeWitnessItems wit ++ post, off := pre.size } wit.length =
      some
        (wit,
          { bs := pre ++ serializeWitnessItems wit ++ post, off := pre.size + (serializeWitnessItems wit).size }) := by
  induction wit generalizing pre post with
  | nil =>
      simp [parseWitnessItems, serializeWitnessItems, concatBytes_nil]
  | cons w ws ih =>
      have hw : witnessItemStructurallyWellFormed' w := h w (by simp)
      have htail : ∀ x, x ∈ ws → witnessItemStructurallyWellFormed' x := by
        intro x hx
        exact h x (by simp [hx])
      rw [serializeWitnessItems_cons]
      simp [parseWitnessItems]
      have hHead :
          parseWitnessItem
            { bs := pre ++ serializeWitnessItem w ++ serializeWitnessItems ws ++ post, off := pre.size } =
          some
            (w,
              {
                bs := pre ++ serializeWitnessItem w ++ serializeWitnessItems ws ++ post,
                off := pre.size + (serializeWitnessItem w).size
              }) := by
        simpa [cursor_bytes_left_assoc] using
          (parseWitnessItem_serializeWitnessItem_between pre w (serializeWitnessItems ws ++ post) hw)
      refine ⟨(w,
          {
            bs := (pre ++ serializeWitnessItem w) ++ serializeWitnessItems ws ++ post,
            off := (pre ++ serializeWitnessItem w).size
          }),
        ?_, ?_⟩
      · simpa [cursor_bytes_left_assoc, ByteArray.size_append, Nat.add_assoc] using hHead
      · refine ⟨(ws,
            {
              bs := (pre ++ serializeWitnessItem w) ++ serializeWitnessItems ws ++ post,
              off := (pre ++ serializeWitnessItem w).size + (serializeWitnessItems ws).size
            }),
          ?_, ?_⟩
        · exact ih (pre := pre ++ serializeWitnessItem w) (post := post) htail
        · constructor
          · constructor <;> rfl
          · simp [serializeWitnessItems_cons, cursor_bytes_left_assoc, ByteArray.size_append, Nat.add_assoc]

theorem parseWitness_serializeWitness_between
    (pre : Bytes)
    (wit : List WitnessItem)
    (post : Bytes)
    (hLen : wit.length ≤ UInt64.size - 1)
    (h : ∀ w, w ∈ wit → witnessItemStructurallyWellFormed' w) :
    parseWitness { bs := pre ++ serializeWitness wit ++ post, off := pre.size } =
      some
        (wit,
          { bs := pre ++ serializeWitness wit ++ post, off := pre.size + (serializeWitness wit).size }) := by
  let countBytes : Bytes := RubinFormal.WireEnc.compactSize wit.length
  have hCount :
      Cursor.getCompactSize? { bs := pre ++ countBytes ++ serializeWitnessItems wit ++ post, off := pre.size } =
        some
          (wit.length,
            {
              bs := pre ++ countBytes ++ serializeWitnessItems wit ++ post,
              off := pre.size + countBytes.size
            },
            true) := by
    simpa [countBytes, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getCompactSize_after_prefix_exact
        (pre := pre)
        (rest := serializeWitnessItems wit ++ post)
        (n := wit.length)
        hLen)
  have hCountExp :
      Cursor.getCompactSize?
        {
          bs := pre ++ (RubinFormal.WireEnc.compactSize wit.length ++ serializeWitnessItems wit) ++ post,
          off := pre.size
        } =
      some
        (wit.length,
          {
            bs := pre ++ (RubinFormal.WireEnc.compactSize wit.length ++ serializeWitnessItems wit) ++ post,
            off := pre.size + countBytes.size
          },
          true) := by
    simpa [countBytes, cursor_bytes_left_assoc, Nat.add_assoc] using hCount
  unfold parseWitness
  unfold serializeWitness
  rw [hCountExp]
  simp [requireMinimal]
  simpa [countBytes, cursor_bytes_left_assoc, Nat.add_assoc, ByteArray.size_append] using
    (parseWitnessItems_serializeWitnessItems_between
      (pre := pre ++ countBytes)
      (wit := wit)
      (post := post)
      h)

end UtxoBasicV1

end RubinFormal
