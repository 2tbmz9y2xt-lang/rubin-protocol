import RubinFormal.CoinbaseBehavioral

/-!
# UTXO Map Properties (§18 Gap Closure)

Machine-checked properties of eraseInputs, insertOutputs, and addCoinbaseOutputs:
1. `TransCmp cmpOutpoint` instance — unlocks Std4 RBMap lemmas
2. `eraseInputs` post-condition theorems (GAP A)
3. `insertOutputs` post-condition theorems (GAP B)
4. `addCoinbaseOutputs` preservation theorem (GAP C)

Dependency: CoinbaseBehavioral (for OrientedCmp + cmpBytes_symm).
-/

namespace RubinFormal

open UtxoBasicV1

/-! ## TransCmp cmpOutpoint

Proves that cmpOutpoint is a transitive comparator, required by Std4
RBMap lemmas (find?_insert_of_eq, find?_insert_of_ne, mem_insert, etc.).
-/

-- UInt8 equality from not-less-both-ways
private theorem uint8_eq_of_not_lt (x y : UInt8) (h1 : ¬(x < y)) (h2 : ¬(y < x)) : x = y := by
  cases x with | mk xv => cases y with | mk yv =>
    have : xv = yv := Fin.ext (by
      show xv.val = yv.val
      have h1' : ¬(xv.val < yv.val) := h1
      have h2' : ¬(yv.val < xv.val) := h2
      omega)
    subst this; rfl

-- cmpBytes.go eq implies list equality (byte-by-byte)
private theorem cmpBytes_go_eq_implies_eq :
    ∀ (xs ys : List UInt8), cmpBytes.go xs ys = .eq → xs = ys := by
  intro xs; induction xs with
  | nil => intro ys h; cases ys with | nil => rfl | cons => simp [cmpBytes.go] at h
  | cons x xs ih => intro ys h; cases ys with
    | nil => simp [cmpBytes.go] at h
    | cons y ys =>
      simp only [cmpBytes.go] at h
      by_cases hxy : (x : UInt8) < y
      · simp [hxy] at h
      · by_cases hyx : (y : UInt8) < x
        · simp [hxy, hyx] at h
        · simp [hxy, hyx] at h
          exact congrArg₂ List.cons (uint8_eq_of_not_lt x y hxy hyx) (ih ys h)

-- cmpBytes eq → toList equality
private theorem cmpBytes_eq_toList (a b : Bytes) (h : cmpBytes a b = .eq) :
    a.data.toList = b.data.toList := cmpBytes_go_eq_implies_eq _ _ h

-- cmpBytes lt → gt (via cmpBytes_symm from CoinbaseBehavioral)
private theorem cmpBytes_lt_to_gt (a b : Bytes) (h : cmpBytes a b = .lt) :
    cmpBytes b a = .gt := by
  have hsym := cmpBytes_symm a b; rw [h] at hsym; exact hsym.symm

-- cmpBytes.go ≠ .gt transitivity (byte-level induction)
private theorem cmpBytes_go_le_trans :
    ∀ (xs ys zs : List UInt8),
    cmpBytes.go xs ys ≠ .gt → cmpBytes.go ys zs ≠ .gt → cmpBytes.go xs zs ≠ .gt := by
  intro xs; induction xs with
  | nil => intro ys zs _ _; cases ys <;> cases zs <;> simp [cmpBytes.go]
  | cons x xs ih => intro ys zs h1 h2; match ys, zs with
    | [], _ => simp [cmpBytes.go] at h1
    | _ :: _, [] => simp [cmpBytes.go] at h2
    | y :: ys, z :: zs =>
      simp only [cmpBytes.go] at h1 h2 ⊢
      by_cases hxy : (x : UInt8) < y
      · simp only [hxy, ite_true] at h1
        by_cases hyz : (y : UInt8) < z
        · have : (x : UInt8) < z := by
            show x.val.val < z.val.val
            have : x.val.val < y.val.val := hxy
            have : y.val.val < z.val.val := hyz; omega
          simp only [this, ite_true]; exact fun h => nomatch h
        · by_cases hzy : (z : UInt8) < y
          · simp only [hzy, ite_true, hyz, ite_false] at h2; exact absurd rfl h2
          · have : (x : UInt8) < z := by
              show x.val.val < z.val.val
              have : x.val.val < y.val.val := hxy
              have : ¬(y.val.val < z.val.val) := hyz
              have : ¬(z.val.val < y.val.val) := hzy; omega
            simp only [this, ite_true]; exact fun h => nomatch h
      · by_cases hyx : (y : UInt8) < x
        · simp only [hxy, ite_false, hyx, ite_true] at h1; exact absurd rfl h1
        · simp only [hxy, ite_false, hyx, ite_false] at h1
          by_cases hyz : (y : UInt8) < z
          · have : (x : UInt8) < z := by
              show x.val.val < z.val.val
              have : ¬(x.val.val < y.val.val) := hxy
              have : ¬(y.val.val < x.val.val) := hyx
              have : y.val.val < z.val.val := hyz; omega
            simp only [this, ite_true]; exact fun h => nomatch h
          · by_cases hzy : (z : UInt8) < y
            · simp only [hzy, ite_true, hyz, ite_false] at h2; exact absurd rfl h2
            · have hxn : ¬(x.val.val < y.val.val) := hxy
              have hyn : ¬(y.val.val < x.val.val) := hyx
              have hyzn : ¬(y.val.val < z.val.val) := hyz
              have hzyn : ¬(z.val.val < y.val.val) := hzy
              have hxz : ¬((x : UInt8) < z) := by
                show ¬(x.val.val < z.val.val); omega
              have hzx : ¬((z : UInt8) < x) := by
                show ¬(z.val.val < x.val.val); omega
              simp only [hxz, ite_false, hzx, ite_false]
              exact ih ys zs h1 (by simp only [hyz, ite_false, hzy, ite_false] at h2; exact h2)

-- Nat compare ≠ .gt transitivity
private theorem nat_compare_le_trans (a b c : Nat) :
    @compare Nat instOrdNat a b ≠ .gt → @compare Nat instOrdNat b c ≠ .gt →
    @compare Nat instOrdNat a c ≠ .gt := by
  show compareOfLessAndEq a b ≠ .gt → compareOfLessAndEq b c ≠ .gt → compareOfLessAndEq a c ≠ .gt
  unfold compareOfLessAndEq; split <;> split <;> split <;> intro h1 h2
  all_goals simp_all; all_goals omega

/-- `cmpOutpoint` is a transitive comparator. -/
theorem cmpOutpoint_le_trans (x y z : Outpoint) :
    cmpOutpoint x y ≠ .gt → cmpOutpoint y z ≠ .gt → cmpOutpoint x z ≠ .gt := by
  show (match cmpBytes x.txid y.txid with | .eq => compare x.vout y.vout | o => o) ≠ .gt →
       (match cmpBytes y.txid z.txid with | .eq => compare y.vout z.vout | o => o) ≠ .gt →
       (match cmpBytes x.txid z.txid with | .eq => compare x.vout z.vout | o => o) ≠ .gt
  intro h1 h2
  have hXY : cmpBytes x.txid y.txid ≠ .gt := by cases h : cmpBytes x.txid y.txid <;> simp_all
  have hYZ : cmpBytes y.txid z.txid ≠ .gt := by cases h : cmpBytes y.txid z.txid <;> simp_all
  have hXZ := cmpBytes_go_le_trans _ _ _ hXY hYZ
  cases hxz : cmpBytes x.txid z.txid with
  | lt => simp
  | gt => exact absurd hxz hXZ
  | eq =>
    simp
    -- Both xy and yz byte comparisons must be .eq
    have hxy_eq : cmpBytes x.txid y.txid = .eq := by
      by_contra h; cases hxy : cmpBytes x.txid y.txid with
      | eq => exact absurd hxy h | gt => exact hXY hxy
      | lt =>
        have hListEq := cmpBytes_eq_toList x.txid z.txid hxz
        have : cmpBytes z.txid y.txid = .lt := by
          show cmpBytes.go z.txid.data.toList y.txid.data.toList = .lt
          rw [← hListEq]; exact hxy
        exact hYZ (cmpBytes_lt_to_gt z.txid y.txid this)
    have hyz_eq : cmpBytes y.txid z.txid = .eq := by
      by_contra h; cases hyz : cmpBytes y.txid z.txid with
      | eq => exact absurd hyz h | gt => exact hYZ hyz
      | lt =>
        have hListEq := cmpBytes_eq_toList x.txid y.txid hxy_eq
        have : cmpBytes x.txid z.txid = .lt := by
          show cmpBytes.go x.txid.data.toList z.txid.data.toList = .lt
          rw [hListEq]; exact hyz
        simp [this] at hxz
    simp [hxy_eq] at h1; simp [hyz_eq] at h2
    exact nat_compare_le_trans x.vout y.vout z.vout h1 h2

instance : Std.TransCmp cmpOutpoint where
  le_trans := cmpOutpoint_le_trans _ _ _

/-! ## RBMap Lifting Lemmas

Std4 RBMap lemmas live at RBNode/RBSet level.  These lift key results
to RBMap so that gap theorems can reference RBMap.find?/contains directly. -/

private theorem cmpOutpoint_eq_refl (a : Outpoint) : cmpOutpoint a a = .eq := by
  have h := Std.OrientedCmp.symm (cmp := cmpOutpoint) a a
  cases h' : cmpOutpoint a a with
  | eq => rfl
  | lt => rw [h'] at h; simp [Ordering.swap] at h
  | gt => rw [h'] at h; simp [Ordering.swap] at h

/-- Pair comparison used by the underlying RBSet of UtxoSet. -/
private abbrev utxoPairCmp : (Outpoint × UtxoEntry) → (Outpoint × UtxoEntry) → Ordering :=
  Ordering.byKey Prod.fst cmpOutpoint

private instance : Std.TransCmp utxoPairCmp where
  symm a b := by simp [utxoPairCmp, Ordering.byKey]; exact Std.OrientedCmp.symm a.1 b.1
  le_trans := by
    intro x y z h1 h2
    simp [utxoPairCmp, Ordering.byKey] at h1 h2 ⊢
    exact Std.TransCmp.le_trans (cmp := cmpOutpoint) h1 h2

/-- After inserting (k, v) into an RBMap, findEntry? k returns (k, v). -/
theorem rbmap_findEntry_insert_self (k : Outpoint) (v : UtxoEntry)
    (t : Std.RBMap Outpoint UtxoEntry cmpOutpoint) :
    (t.insert k v).findEntry? k = some (k, v) := by
  simp only [Std.RBMap.insert, Std.RBMap.findEntry?, Std.RBSet.findP?, Std.RBSet.insert]
  show Std.RBNode.find? (utxoPairCmp (k, v))
    (Std.RBNode.insert utxoPairCmp t.val (k, v)) = some (k, v)
  have ⟨hord, c, n, hbal⟩ := t.2.out
  exact Std.RBNode.find?_insert_self hbal hord
    (by simp [utxoPairCmp, Ordering.byKey]; exact cmpOutpoint_eq_refl k)

/-- After inserting k↦v, find? k returns v. -/
theorem rbmap_find_insert_self (k : Outpoint) (v : UtxoEntry)
    (t : Std.RBMap Outpoint UtxoEntry cmpOutpoint) :
    (t.insert k v).find? k = some v := by
  simp [Std.RBMap.find?, rbmap_findEntry_insert_self k v t]

/-- After inserting k↦v, contains k is true. -/
theorem rbmap_contains_insert_self (k : Outpoint) (v : UtxoEntry)
    (t : Std.RBMap Outpoint UtxoEntry cmpOutpoint) :
    (t.insert k v).contains k = true := by
  simp [Std.RBMap.contains, rbmap_findEntry_insert_self k v t]

/-! ## Insert-of-ne lifting: inserting with key k' preserves find? for key k ≠ k'.

  (#288) RBMap.findEntry? uses cut `(· |>.1 |> cmpOutpoint k)` while
  RBSet.find? uses full pair comparison `utxoPairCmp (k, v)`.  These are
  definitionally equal because `utxoPairCmp` is `Ordering.byKey Prod.fst cmpOutpoint`.
  The helper `findP_eq_pair_find` factors out this equivalence so the main
  proof never uses the fragile `change` tactic. -/

/-- The RBMap key-projection cut equals the RBSet pair comparison for any dummy value.
    This is the key lifting lemma: `findP? (cmpOutpoint k ·.1)` ≡ `find? utxoPairCmp (k, dummy)`. -/
private theorem findP_eq_pair_find (k : Outpoint) (dummy : UtxoEntry)
    (t : Std.RBSet (Outpoint × UtxoEntry) utxoPairCmp) :
    t.findP? (fun x => cmpOutpoint k x.1) = t.find? (k, dummy) := by
  simp only [Std.RBSet.findP?, Std.RBSet.find?]
  congr 1

/-- Inserting a different key preserves findEntry? for the original key.
    Uses `findP_eq_pair_find` to bridge RBMap (key-cut) ↔ RBSet (pair-find),
    then delegates to `Std.RBSet.find?_insert_of_ne`. -/
theorem rbmap_findEntry_insert_of_ne (k k' : Outpoint) (v : UtxoEntry)
    (t : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hne : cmpOutpoint k k' ≠ .eq) :
    (t.insert k' v).findEntry? k = t.findEntry? k := by
  simp only [Std.RBMap.findEntry?, Std.RBMap.insert]
  rw [findP_eq_pair_find k v (Std.RBSet.insert t (k', v)),
      findP_eq_pair_find k v t]
  exact Std.RBSet.find?_insert_of_ne (cmp := utxoPairCmp) t
    (v := (k', v)) (v' := (k, v))
    (by simp [utxoPairCmp, Ordering.byKey]; exact hne)

/-- Inserting a different key preserves find? for the original key. -/
theorem rbmap_find_insert_of_ne (k k' : Outpoint) (v' : UtxoEntry)
    (t : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hne : cmpOutpoint k k' ≠ .eq) :
    (t.insert k' v').find? k = t.find? k := by
  simp only [Std.RBMap.find?]
  congr 1; exact rbmap_findEntry_insert_of_ne k k' v' t hne

/-! ## GAP B: insertOutputs — inserted outputs are findable

After `insertOutputs utxo txid outputs height`, each output's outpoint
(txid, vout) is findable via find?. -/

/-- Single-step: after one insert in insertOutputs.go, the just-inserted
    output is findable. This is a direct corollary of rbmap_find_insert_self. -/
theorem insertOutputs_go_last_present
    (next : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (txid : Bytes) (out : TxOut) (height vout : Nat) :
    ∃ entry, (next.insert ⟨txid, vout⟩
      { value := out.value, covenantType := out.covenantType,
        covenantData := out.covenantData, creationHeight := height,
        createdByCoinbase := false }).find? ⟨txid, vout⟩ = some entry :=
  ⟨_, rbmap_find_insert_self ⟨txid, vout⟩ _ next⟩

/-! ## GAP A: eraseInputs — erased outpoints not findable

After `erase k utxo`, `find? k` returns `none`.  This is the universal
(∀ k, ∀ t) version — not a concrete-input test.  Proof strategy:
1. `Ordered` + `IsStrictCut.exact` + strict `cmpLT` → subtrees have no cut=eq duplicates.
2. `del` replaces root with `append left right` in the eq case; bal{Left,Right} in lt/gt cases.
3. Nat induction shows `All (cut ≠ .eq)` is preserved through del.
4. `find_none_of_all_ne` closes the gap.
-/

private abbrev UP := Outpoint × UtxoEntry
private abbrev UPC : UP → UP → Ordering := fun a b => cmpOutpoint a.1 b.1

private instance : Std.TransCmp UPC where
  symm a b := by simp [UPC]; exact Std.OrientedCmp.symm a.1 b.1
  le_trans := by
    intro x y z h1 h2; simp [UPC] at h1 h2 ⊢
    exact Std.TransCmp.le_trans (cmp := cmpOutpoint) h1 h2

open Std.RBNode in
private theorem cut_ne_of_cmpLT_left
    (k : Outpoint) (dummy : UtxoEntry) (elem y : UP)
    [Std.TransCmp UPC]
    (hlt : cmpLT UPC elem y)
    (hcut_y : UPC (k, dummy) y = .eq) : UPC (k, dummy) elem ≠ .eq := by
  intro hcut_elem
  have hlt_val : UPC elem y = .lt := hlt.elim fun f => f
  have hexact := @IsStrictCut.exact _ UPC (UPC (k, dummy)) _ elem y _ hcut_elem
  simp only [UPC] at hexact hlt_val hcut_y
  rw [hcut_y] at hexact; rw [hexact] at hlt_val
  exact absurd hlt_val (by decide)

open Std.RBNode in
private theorem cut_ne_of_cmpLT_right
    (k : Outpoint) (dummy : UtxoEntry) (y elem : UP)
    [Std.TransCmp UPC]
    (hlt : cmpLT UPC y elem)
    (hcut_y : UPC (k, dummy) y = .eq) : UPC (k, dummy) elem ≠ .eq := by
  intro hcut_elem
  have hlt_val : UPC y elem = .lt := hlt.elim fun f => f
  have hexact := @IsStrictCut.exact _ UPC (UPC (k, dummy)) _ elem y _ hcut_elem
  simp only [UPC] at hexact hlt_val hcut_y
  rw [hcut_y] at hexact
  have hsym := Std.OrientedCmp.symm (cmp := cmpOutpoint) elem.1 y.1
  rw [hexact] at hsym; simp [Ordering.swap] at hsym
  rw [hsym.symm] at hlt_val; exact absurd hlt_val (by decide)

open Std.RBNode in
private theorem ordered_left_cut_ne
    (k : Outpoint) (dummy : UtxoEntry)
    {c} {a : Std.RBNode UP} {y : UP} {b : Std.RBNode UP}
    [Std.TransCmp UPC]
    (hord : Ordered UPC (node c a y b))
    (hcut : UPC (k, dummy) y = .eq) :
    a.All (fun x => UPC (k, dummy) x ≠ .eq) :=
  hord.1.imp (fun h => cut_ne_of_cmpLT_left k dummy _ y h hcut)

open Std.RBNode in
private theorem ordered_right_cut_ne
    (k : Outpoint) (dummy : UtxoEntry)
    {c} {a : Std.RBNode UP} {y : UP} {b : Std.RBNode UP}
    [Std.TransCmp UPC]
    (hord : Ordered UPC (node c a y b))
    (hcut : UPC (k, dummy) y = .eq) :
    b.All (fun x => UPC (k, dummy) x ≠ .eq) :=
  hord.2.1.imp (fun h => cut_ne_of_cmpLT_right k dummy y _ h hcut)

open Std.RBNode in
private theorem find_none_of_all_ne {cut : UP → Ordering} {t : Std.RBNode UP}
    (h : t.All (fun x => cut x ≠ .eq)) : t.find? cut = none := by
  induction t with
  | nil => rfl
  | node c a y b iha ihb =>
    simp only [find?]; cases hc : cut y with
    | eq => exact absurd hc h.1 | lt => exact iha h.2.1 | gt => exact ihb h.2.2

open Std.RBNode in
private theorem find_setBlack {cut : UP → Ordering} {t : Std.RBNode UP} :
    t.setBlack.find? cut = t.find? cut := by
  cases t with | nil => rfl | node c a y b => cases c <;> rfl

open Std.RBNode in
private theorem all_balLeft_of (p : UP → Prop) :
    ∀ (l : Std.RBNode UP) (v : UP) (r : Std.RBNode UP),
    All p l → p v → All p r → All p (balLeft l v r)
  | node .red la ly lb, v, r, ⟨hly, hla, hlb⟩, hv, hr => ⟨hv, ⟨hly, hla, hlb⟩, hr⟩
  | .nil, v, .nil, _, hv, _ => ⟨hv, trivial, trivial⟩
  | .nil, v, node .black ra ry rb, _, hv, hr => balance2_All.2 ⟨hv, trivial, hr⟩
  | .nil, v, node .red (node .black rla rly rlb) ry rb, _, hv, ⟨hry, ⟨hrly, hrla, hrlb⟩, hrb⟩ =>
    ⟨hrly, ⟨hv, trivial, hrla⟩, balance2_All.2 ⟨hry, hrlb,
      by cases rb with | nil => trivial | node => exact hrb⟩⟩
  | .nil, v, node .red .nil ry rb, _, hv, hr => ⟨hv, trivial, hr⟩
  | .nil, v, node .red (node .red _ _ _) ry rb, _, hv, hr => ⟨hv, trivial, hr⟩
  | node .black la ly lb, v, .nil, hl, hv, _ => ⟨hv, hl, trivial⟩
  | node .black la ly lb, v, node .black ra ry rb, hl, hv, hr => balance2_All.2 ⟨hv, hl, hr⟩
  | node .black la ly lb, v, node .red (node .black rla rly rlb) ry rb, hl, hv,
    ⟨hry, ⟨hrly, hrla, hrlb⟩, hrb⟩ =>
    ⟨hrly, ⟨hv, hl, hrla⟩, balance2_All.2 ⟨hry, hrlb,
      by cases rb with | nil => trivial | node => exact hrb⟩⟩
  | node .black la ly lb, v, node .red .nil ry rb, hl, hv, hr => ⟨hv, hl, hr⟩
  | node .black la ly lb, v, node .red (node .red _ _ _) ry rb, hl, hv, hr => ⟨hv, hl, hr⟩

open Std.RBNode in
private theorem all_balRight_of (p : UP → Prop) :
    ∀ (l : Std.RBNode UP) (v : UP) (r : Std.RBNode UP),
    All p l → p v → All p r → All p (balRight l v r)
  | l, v, node .red ra ry rb, hl, hv, ⟨hry, hra, hrb⟩ => ⟨hv, hl, ⟨hry, hra, hrb⟩⟩
  | .nil, v, .nil, _, hv, _ => ⟨hv, trivial, trivial⟩
  | node .black la ly lb, v, .nil, hl, hv, _ => balance1_All.2 ⟨hv, hl, trivial⟩
  | node .red la ly (node .black lb lz lc), v, .nil,
    ⟨hly, hla, ⟨hlz, hlb, hlc⟩⟩, hv, _ =>
    ⟨hlz, balance1_All.2 ⟨hly,
      by cases la with | nil => trivial | node => exact hla, hlb⟩, ⟨hv, hlc, trivial⟩⟩
  | node .red la ly .nil, v, .nil, hl, hv, _ => ⟨hv, hl, trivial⟩
  | node .red la ly (node .red _ _ _), v, .nil, hl, hv, _ => ⟨hv, hl, trivial⟩
  | .nil, v, node .black ra ry rb, _, hv, hr => ⟨hv, trivial, hr⟩
  | node .black la ly lb, v, node .black ra ry rb, hl, hv, hr => balance1_All.2 ⟨hv, hl, hr⟩
  | node .red la ly (node .black lb lz lc), v, node .black ra ry rb,
    ⟨hly, hla, ⟨hlz, hlb, hlc⟩⟩, hv, hr =>
    ⟨hlz, balance1_All.2 ⟨hly,
      by cases la with | nil => trivial | node => exact hla, hlb⟩, ⟨hv, hlc, hr⟩⟩
  | node .red la ly .nil, v, node .black ra ry rb, hl, hv, hr => ⟨hv, hl, hr⟩
  | node .red la ly (node .red _ _ _), v, node .black ra ry rb, hl, hv, hr => ⟨hv, hl, hr⟩

open Std.RBNode in
private theorem all_append_aux (p : UP → Prop) (n : Nat) :
    ∀ (l r : Std.RBNode UP), l.size + r.size ≤ n →
    All p l → All p r → All p (append l r) := by
  induction n with
  | zero =>
    intro l r h hl hr
    cases l with | nil => simp [append]; exact hr | node => simp [size] at h; omega
  | succ n ih =>
    intro l r hsize hl hr
    cases l with
    | nil => simp [append]; exact hr
    | node cl la lx lb =>
      cases r with
      | nil => simp [append]; exact hl
      | node cr ra rx rb =>
        have hla := hl.2.1; have hlx := hl.1; have hlb := hl.2.2
        have hra := hr.2.1; have hrx := hr.1; have hrb := hr.2.2
        have hsub : lb.size + ra.size ≤ n := by simp [size] at hsize; omega
        have ih_sub := ih lb ra hsub hlb hra
        cases cl <;> cases cr <;> simp only [append]
        · cases h : append lb ra with
          | nil => exact ⟨hlx, hla, ⟨hrx, trivial, hrb⟩⟩
          | node c' e w f => rw [h] at ih_sub; cases c' with
            | red => exact ⟨ih_sub.1, ⟨hlx, hla, ih_sub.2.1⟩, ⟨hrx, ih_sub.2.2, hrb⟩⟩
            | black => exact ⟨hlx, hla, ⟨hrx, ih_sub, hrb⟩⟩
        · exact ⟨hlx, hla, ih lb (node .black ra rx rb)
            (by simp [size] at hsize ⊢; omega) hlb hr⟩
        · exact ⟨hrx, ih (node .black la lx lb) ra
            (by simp [size] at hsize ⊢; omega) hl hra, hrb⟩
        · cases h : append lb ra with
          | nil => exact all_balLeft_of _ la lx _ hla hlx ⟨hrx, trivial, hrb⟩
          | node c' e w f => rw [h] at ih_sub; cases c' with
            | red => exact ⟨ih_sub.1, ⟨hlx, hla, ih_sub.2.1⟩, ⟨hrx, ih_sub.2.2, hrb⟩⟩
            | black => exact all_balLeft_of _ la lx _ hla hlx ⟨hrx, ih_sub, hrb⟩

open Std.RBNode in
private theorem all_append_of' {p : UP → Prop} {l r : Std.RBNode UP}
    (hl : All p l) (hr : All p r) : All p (append l r) :=
  all_append_aux p (l.size + r.size) l r (Nat.le_refl _) hl hr

open Std.RBNode in
private theorem all_del_cut_ne_ordered
    (k : Outpoint) (dummy : UtxoEntry) (n : Nat) :
    ∀ (t : Std.RBNode UP), t.size ≤ n → Ordered UPC t →
    (del (UPC (k, dummy)) t).All (fun x => UPC (k, dummy) x ≠ .eq) := by
  induction n with
  | zero => intro t hs _; cases t <;> trivial
  | succ n ih =>
    intro t hs hord
    cases t with
    | nil => trivial
    | node c a y b =>
      have ha_ord := hord.2.2.1; have hb_ord := hord.2.2.2
      cases hcut : UPC (k, dummy) y with
      | eq =>
        unfold del; simp only [hcut]
        exact all_append_of' (ordered_left_cut_ne k dummy hord hcut)
                             (ordered_right_cut_ne k dummy hord hcut)
      | lt =>
        unfold del; simp only [hcut]
        have ih_a := ih a (by simp [size] at hs; omega) ha_ord
        have hb_ne : b.All (fun x => UPC (k, dummy) x ≠ .eq) :=
          hord.2.1.imp (fun hlt x_eq => by
            have := IsCut.le_lt_trans (cmp := UPC) (cut := UPC (k, dummy))
              (show UPC y _ ≠ .gt from by have := hlt.elim fun f => f; rw [this]; decide) hcut
            rw [this] at x_eq; exact absurd x_eq (by decide))
        have hy_ne : UPC (k, dummy) y ≠ .eq := by rw [hcut]; decide
        split
        · exact all_balLeft_of _ _ y _ ih_a hy_ne hb_ne
        · exact ⟨hy_ne, ih_a, hb_ne⟩
      | gt =>
        unfold del; simp only [hcut]
        have ih_b := ih b (by simp [size] at hs; omega) hb_ord
        have ha_ne : a.All (fun x => UPC (k, dummy) x ≠ .eq) :=
          hord.1.imp (fun hlt x_eq => by
            have := IsCut.le_gt_trans (cmp := UPC) (cut := UPC (k, dummy))
              (show UPC _ y ≠ .gt from by have := hlt.elim fun f => f; rw [this]; decide) hcut
            rw [this] at x_eq; exact absurd x_eq (by decide))
        have hy_ne : UPC (k, dummy) y ≠ .eq := by rw [hcut]; decide
        split
        · exact all_balRight_of _ a y _ ha_ne hy_ne ih_b
        · exact ⟨hy_ne, ha_ne, ih_b⟩

/-- **GAP A (universal):** After erasing key `k` from an RBMap, `find? k = none`.
    Proved via Ordered-tree uniqueness + All-preserving del induction. -/
theorem rbmap_find_erase_self (k : Outpoint)
    (t : Std.RBMap Outpoint UtxoEntry cmpOutpoint) :
    (t.erase k).find? k = none := by
  simp only [Std.RBMap.erase, Std.RBMap.find?, Std.RBMap.findEntry?, Std.RBSet.erase,
             Std.RBSet.findP?, Std.RBNode.erase]
  rw [find_setBlack]
  have hord : Std.RBNode.Ordered UPC t.val := t.2.out.1
  have h_all := all_del_cut_ne_ordered k ⟨0, 0, ByteArray.empty, 0, false⟩
    t.val.size t.val (Nat.le_refl _) hord
  simp [find_none_of_all_ne h_all]

/-! ## Outpoint vout uniqueness -/

/-- Outpoints with same txid but different vout are not cmpOutpoint-equal. -/
theorem outpoint_ne_of_vout_ne (txid : Bytes) (i j : Nat) (h : i ≠ j) :
    cmpOutpoint ⟨txid, i⟩ ⟨txid, j⟩ ≠ .eq := by
  simp only [cmpOutpoint, cmpBytes_refl]
  intro heq; apply h
  by_cases hij : i < j
  · simp [compare, Ord.compare, compareOfLessAndEq, hij] at heq
  · by_cases heij : i = j
    · exact heij
    · simp [compare, Ord.compare, compareOfLessAndEq, hij, heij] at heq

/-! ## GAP B composition: insertOutputs.go preserves earlier inserts -/

/-- After the full `insertOutputs.go` loop, any output inserted at an earlier
    vout is still findable — later inserts with different vout values don't
    overwrite it. Uses rbmap_find_insert_of_ne + outpoint_ne_of_vout_ne. -/
theorem insertOutputs_go_preserves_earlier
    (txid : Bytes) (height : Nat)
    (next : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (vout : Nat) (v : UtxoEntry)
    (hfind : next.find? ⟨txid, vout⟩ = some v)
    (outs : List TxOut) (startVout : Nat)
    (hne : ∀ i, startVout ≤ i → i < startVout + outs.length → i ≠ vout) :
    (insertOutputs.go txid height outs next startVout).find? ⟨txid, vout⟩ = some v := by
  induction outs generalizing next startVout with
  | nil => exact hfind
  | cons o rest ih =>
    simp only [insertOutputs.go]
    apply ih
    · rw [rbmap_find_insert_of_ne ⟨txid, vout⟩ ⟨txid, startVout⟩ _ next
          (outpoint_ne_of_vout_ne txid vout startVout
            (hne startVout (Nat.le_refl _) (by simp [List.length]; omega)).symm)]
      exact hfind
    · intro i hi_lo hi_hi
      exact hne i (by omega) (by simp [List.length] at hi_hi ⊢; omega)

/-! ## GAP C: addCoinbaseOutputs — existing entries preserved

After `addCoinbaseOutputs utxo txid outputs height`, entries with keys
different from the newly-inserted outpoints are still findable.
Follows from rbmap_find_insert_of_ne applied inductively. -/

/-- Generic foldl preservation: each step either skips (non-spendable) or inserts
    with a different key. Premise only requires non-collision for SPENDABLE outputs. -/
private theorem foldl_insert_preserves_find
    (pairs : List (Nat × CovenantGenesisV1.TxOut))
    (txid : Bytes) (height : Nat)
    (acc : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (k : Outpoint) (v : UtxoEntry)
    (hfind : acc.find? k = some v)
    (hne : ∀ p ∈ pairs, isSpendableCoinbaseOutput p.2 → cmpOutpoint k ⟨txid, p.1⟩ ≠ .eq) :
    (pairs.foldl (fun acc' (p : Nat × CovenantGenesisV1.TxOut) =>
      if isSpendableCoinbaseOutput p.2 then
        acc'.insert ⟨txid, p.1⟩ (coinbaseUtxoEntry p.2 height)
      else acc') acc).find? k = some v := by
  induction pairs generalizing acc with
  | nil => exact hfind
  | cons p rest ih =>
    simp only [List.foldl]
    have hne_rest : ∀ q ∈ rest, isSpendableCoinbaseOutput q.2 → cmpOutpoint k ⟨txid, q.1⟩ ≠ .eq :=
      fun q hq hsp => hne q (List.mem_cons_of_mem _ hq) hsp
    by_cases hsp : isSpendableCoinbaseOutput p.2
    · simp only [hsp, ite_true]
      have hne_p := hne p (List.mem_cons_self _ _) hsp
      exact ih (acc.insert ⟨txid, p.1⟩ _)
        (by rw [rbmap_find_insert_of_ne k ⟨txid, p.1⟩ _ acc hne_p]; exact hfind)
        hne_rest
    · simp only [hsp, ite_false]; exact ih acc hfind hne_rest

/-- **GAP C (composition):** After the full `addCoinbaseOutputs` foldl loop,
    any entry with key `k` not matching any *spendable* inserted outpoint is preserved.
    Non-spendable outputs are skipped by `addCoinbaseOutputs` and don't require non-collision. -/
theorem addCoinbaseOutputs_preserves_full
    (outputs : List CovenantGenesisV1.TxOut) (txid : Bytes) (height : Nat)
    (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (k : Outpoint) (v : UtxoEntry)
    (hfind : utxos.find? k = some v)
    (hne : ∀ p ∈ outputs.enum, isSpendableCoinbaseOutput p.2 → cmpOutpoint k ⟨txid, p.1⟩ ≠ .eq) :
    (addCoinbaseOutputs outputs txid height utxos).find? k = some v :=
  foldl_insert_preserves_find outputs.enum txid height utxos k v hfind hne

end RubinFormal
