import Std

/-!
Bounded model of the proposed comparison of a committed root of `U_parent` and
committed nodes at the routing path of an outpoint that input resolution
resolved as a present entry of `U_parent` (rubin-spec
`RUBIN_CONSENSUS_STATE_MACHINE.md` Sections 2.5 and 2.6 at
846fb249097f82c639fb47eb46d1f1c8cbd8f3f4, with the proposed root-derivation
sentences). Keys are bit lists of a width `w`; the registered statement fixes
`w = 288`, so the depth bound 287 is `w - 1`. Events carry their position: the
model does not represent hashing, root bytes, leaf entry bytes, store reads,
the derivation of `Root(U_candidate)` or how a result comes to identify a node.
It is a model property with no bridge to Go or Rust code.
-/
namespace RubinFormal.RootPathComparisonV1

/-- A routing key as its bits, bit 0 first. -/
abbrev Key := List Bool

/-- `bit k i`; false at and above the key width. -/
def bit : Key → Nat → Bool
  | [], _ => false
  | b :: _, 0 => b
  | _ :: k, i + 1 => bit k i

/-- `Mask36`: keeps bits below `d` and zeroes the rest; length is preserved. -/
def mask : Key → Nat → Key
  | [], _ => []
  | _ :: k, 0 => false :: mask k 0
  | b :: k, d + 1 => b :: mask k d

inductive Node where
  | empty
  | leaf (key : Key)
  | branch (depth : Nat) (pfx : Key)
  deriving DecidableEq

/-- TOP is the canonical node of `U_parent`; CHILD is the child on `side` of an
identified branch with depth `depth` and prefix `pfx`. -/
inductive Pos where
  | top
  | child (depth : Nat) (pfx : Key) (side : Bool)
  deriving DecidableEq

/-- An obtained result: a root (abstracted to whether it equals the empty-map
digest), a node identity at a position, or a node identity at no position. -/
inductive Result where
  | root (isEmptyDigest : Bool)
  | atPos (pos : Pos) (node : Node)
  | noPos (node : Node)
  deriving DecidableEq

inductive Event where
  | obtain (r : Result)
  | consume
  | unavailable
  deriving DecidableEq

inductive Finding where
  | failedCheck
  | unavailableRead
  deriving DecidableEq

/-- The node rule at a compared position; `parent` is the depth of the parent
branch at a compared CHILD and `none` at TOP. -/
def nodeOk (w : Nat) (K : Key) (parent : Option Nat) : Node → Bool
  | .empty => false
  | .leaf k => decide (k = K)
  | .branch d' p =>
      (match parent with
        | none => true
        | some d => decide (d < d')) &&
      decide (d' ≤ w - 1) && decide (p = mask K d')

/-- A CHILD is compared for `K` when its parent has a depth of at most `w - 1`,
the prefix `mask K d` and the side `bit K d`. -/
def comparedChild (w : Nat) (K : Key) (d : Nat) (p : Key) (s : Bool) : Bool :=
  decide (d ≤ w - 1) && decide (p = mask K d) && decide (s = bit K d)

def nodePasses (w : Nat) (K : Key) : Pos → Node → Bool
  | .top, n => nodeOk w K none n
  | .child d p s, n => !comparedChild w K d p s || nodeOk w K (some d) n

def resultPassesFor (w : Nat) (K : Key) : Result → Bool
  | .root e => !e
  | .atPos pos n => nodePasses w K pos n
  | .noPos _ => true

def resultPasses (w : Nat) (present : List Key) (r : Result) : Bool :=
  present.all (fun K => resultPassesFor w K r)

/-- The first unavailable event or obtain of a non-passing result decides. -/
def firstFinding (w : Nat) (present : List Key) : List Event → Option Finding
  | [] => none
  | .consume :: es => firstFinding w present es
  | .unavailable :: _ => some .unavailableRead
  | .obtain r :: es =>
      if resultPasses w present r then firstFinding w present es else some .failedCheck

/-! Canonical tree (Section 2.6): a branch has depth `d` at which its keys first
differ, the prefix `mask` of its keys, and its zero-bit subtree first. -/

inductive Tree where
  | leaf (key : Key)
  | branch (depth : Nat) (pfx : Key) (zero one : Tree)

def Tree.keys : Tree → List Key
  | .leaf k => [k]
  | .branch _ _ l r => l.keys ++ r.keys

def Tree.node : Tree → Node
  | .leaf k => .leaf k
  | .branch d p _ _ => .branch d p

def Canonical (w : Nat) : Tree → Prop
  | .leaf k => k.length = w
  | .branch d p l r =>
      d < w ∧ (∀ k, k ∈ l.keys ++ r.keys → mask k d = p) ∧
      (∀ k, k ∈ l.keys → bit k d = false) ∧ (∀ k, k ∈ r.keys → bit k d = true) ∧
      Canonical w l ∧ Canonical w r

instance decCanonical (w : Nat) : (t : Tree) → Decidable (Canonical w t)
  | .leaf k => inferInstanceAs (Decidable (k.length = w))
  | .branch d p l r =>
      have := decCanonical w l
      have := decCanonical w r
      inferInstanceAs (Decidable (d < w ∧ (∀ k, k ∈ l.keys ++ r.keys → mask k d = p) ∧
        (∀ k, k ∈ l.keys → bit k d = false) ∧ (∀ k, k ∈ r.keys → bit k d = true) ∧
        Canonical w l ∧ Canonical w r))

/-- `Sub s t`: `s` is a subtree of `t`. -/
inductive Sub : Tree → Tree → Prop
  | refl (t : Tree) : Sub t t
  | zero {s l r : Tree} {d : Nat} {p : Key} : Sub s l → Sub s (.branch d p l r)
  | one {s l r : Tree} {d : Nat} {p : Key} : Sub s r → Sub s (.branch d p l r)

/-- The results at the path positions of `K` in a tree. -/
def Tree.pathResults (K : Key) : Pos → Tree → List Result
  | pos, .leaf k => [.atPos pos (.leaf k)]
  | pos, .branch d p l r =>
      .atPos pos (.branch d p) ::
        (cond (bit K d) (Tree.pathResults K (.child d p true) r)
          (Tree.pathResults K (.child d p false) l))

/-! Path of `K` through an arbitrary assignment of node identities. -/

def step (K : Key) (f : Pos → Node) (pos : Pos) : Option Pos :=
  match f pos with
  | .branch d p => some (.child d p (bit K d))
  | _ => none

def pathAt (K : Key) (f : Pos → Node) : Nat → Option Pos
  | 0 => some .top
  | i + 1 => (pathAt K f i).bind (step K f)

/-- A position compared for `K`. -/
def Compared (w : Nat) (K : Key) (pos : Pos) : Prop :=
  pos = .top ∨ ∃ d, d ≤ w - 1 ∧ pos = .child d (mask K d) (bit K d)

def FailsFirst (w : Nat) (present : List Key) (es : List Event) : Prop :=
  ∃ pre r post, es = pre ++ Event.obtain r :: post ∧
    resultPasses w present r = false ∧ Event.unavailable ∉ pre

def UnavailableFirst (w : Nat) (present : List Key) (es : List Event) : Prop :=
  ∃ pre post, es = pre ++ Event.unavailable :: post ∧
    ∀ r, Event.obtain r ∈ pre → resultPasses w present r = true

def Event.isConsume : Event → Bool
  | .consume => true
  | _ => false

/-! Key lemmas. -/

theorem bit_mask (k : Key) (d i : Nat) : bit (mask k d) i = (decide (i < d) && bit k i) := by
  induction k generalizing d i with
  | nil => cases d <;> cases i <;> simp [mask, bit]
  | cons b k ih =>
    cases d with
    | zero => cases i <;> simp [mask, bit, ih, Nat.not_lt_zero]
    | succ d =>
      cases i with
      | zero => simp [mask, bit]
      | succ i => simp [mask, bit, ih, Nat.succ_lt_succ_iff]

theorem bit_eq_of_mask_eq {a b : Key} {d i : Nat} (h : mask a d = mask b d) (hi : i < d) :
    bit a i = bit b i := by
  have := congrArg (fun k => bit k i) h
  simpa [bit_mask, hi] using this

theorem keys_nonempty : (t : Tree) → ∃ k, k ∈ t.keys
  | .leaf k => ⟨k, by simp [Tree.keys]⟩
  | .branch _ _ l _ =>
    let ⟨k, hk⟩ := keys_nonempty l
    ⟨k, by simp [Tree.keys, hk]⟩

theorem sub_keys {s t : Tree} (h : Sub s t) {k : Key} (hk : k ∈ s.keys) : k ∈ t.keys := by
  induction h with
  | refl => exact hk
  | zero _ ih => simp [Tree.keys, ih]
  | one _ ih => simp [Tree.keys, ih]

theorem sub_canonical {w : Nat} {s t : Tree} (h : Sub s t) (ht : Canonical w t) : Canonical w s := by
  induction h with
  | refl => exact ht
  | zero _ ih => exact ih ht.2.2.2.2.1
  | one _ ih => exact ih ht.2.2.2.2.2

/-- A canonical branch whose keys all agree on every bit at or below `d0` has
a depth greater than `d0`. -/
theorem depth_gt_of_agree {w d0 d : Nat} {p : Key} {l r : Tree}
    (hc : Canonical w (.branch d p l r))
    (hagree : ∀ a b, a ∈ (Tree.branch d p l r).keys → b ∈ (Tree.branch d p l r).keys →
      ∀ i, i ≤ d0 → bit a i = bit b i) : d0 < d := by
  obtain ⟨kl, hkl⟩ := keys_nonempty l
  obtain ⟨kr, hkr⟩ := keys_nonempty r
  have hl := hc.2.2.1 kl hkl
  have hr := hc.2.2.2.1 kr hkr
  apply Nat.lt_of_not_le
  intro hle
  have := hagree kl kr (by simp [Tree.keys, hkl]) (by simp [Tree.keys, hkr]) d hle
  rw [hl, hr] at this
  exact Bool.noConfusion this

/-- Within a canonical branch, every branch of the zero (one) subtree is
deeper than it. -/
theorem depth_gt_in_side {w d0 d : Nat} {p0 p : Key} {l r sl sr : Tree}
    (hc : Canonical w (.branch d0 p0 l r)) (side : Bool)
    (hs : Sub (.branch d p sl sr) (cond side r l)) : d0 < d := by
  have hcs : Canonical w (.branch d p sl sr) := by
    cases side
    · exact sub_canonical hs hc.2.2.2.2.1
    · exact sub_canonical hs hc.2.2.2.2.2
  apply depth_gt_of_agree hcs
  intro a b ha hb i hi
  have ha' := sub_keys hs ha
  have hb' := sub_keys hs hb
  have hmem : ∀ k, k ∈ (cond side r l).keys → k ∈ l.keys ++ r.keys := by
    intro k hk; cases side <;> simp_all
  rcases Nat.lt_or_eq_of_le hi with hlt | heq
  · have hma := hc.2.1 a (hmem a ha')
    have hmb := hc.2.1 b (hmem b hb')
    exact bit_eq_of_mask_eq (hma.trans hmb.symm) hlt
  · subst heq
    cases side
    · rw [hc.2.2.1 a ha', hc.2.2.1 b hb']
    · rw [hc.2.2.2.1 a ha', hc.2.2.2.1 b hb']

/-- A branch of a canonical tree that holds `K` and whose prefix is `mask K d`
holds `K`. -/
theorem mem_of_sub_prefix {w : Nat} {K : Key} {s t : Tree} (h : Sub s t) :
    ∀ {d p sl sr}, s = .branch d p sl sr → Canonical w t → K ∈ t.keys → p = mask K d →
      K ∈ s.keys := by
  induction h with
  | refl => intro _ _ _ _ _ _ hK _; exact hK
  | @zero l r d0 p0 hsub ih =>
    intro d p sl sr hs hc hK hp
    have hK' : K ∈ l.keys ∨ K ∈ r.keys := by simpa [Tree.keys] using hK
    rcases hK' with hl | hr
    · exact ih hs hc.2.2.2.2.1 hl hp
    · exfalso
      subst hs
      have hlt := depth_gt_in_side hc false hsub
      have hcs := sub_canonical hsub hc.2.2.2.2.1
      obtain ⟨k, hk⟩ := keys_nonempty (Tree.branch d p sl sr)
      have hmk := hcs.2.1 k (by simpa [Tree.keys] using hk)
      have hb := bit_eq_of_mask_eq (hmk.trans hp) hlt
      have hk0 := hc.2.2.1 k (sub_keys hsub hk)
      have hK1 := hc.2.2.2.1 K hr
      rw [hk0, hK1] at hb
      exact Bool.noConfusion hb
  | @one l r d0 p0 hsub ih =>
    intro d p sl sr hs hc hK hp
    have hK' : K ∈ l.keys ∨ K ∈ r.keys := by simpa [Tree.keys] using hK
    rcases hK' with hl | hr
    · exfalso
      subst hs
      have hlt := depth_gt_in_side hc true hsub
      have hcs := sub_canonical hsub hc.2.2.2.2.2
      obtain ⟨k, hk⟩ := keys_nonempty (Tree.branch d p sl sr)
      have hmk := hcs.2.1 k (by simpa [Tree.keys] using hk)
      have hb := bit_eq_of_mask_eq (hmk.trans hp) hlt
      have hk1 := hc.2.2.2.1 k (sub_keys hsub hk)
      have hK0 := hc.2.2.1 K hl
      rw [hk1, hK0] at hb
      exact Bool.noConfusion hb
    · exact ih hs hc.2.2.2.2.2 hr hp

/-! Part (a): soundness on the canonical tree. -/

theorem top_passes {w : Nat} {K : Key} {t : Tree} (hc : Canonical w t) (hK : K ∈ t.keys) :
    nodePasses w K .top t.node = true := by
  cases t with
  | leaf k =>
    have : K = k := by simpa [Tree.keys] using hK
    subst this
    simp [nodePasses, nodeOk, Tree.node]
  | branch d p l r =>
    have hd : d ≤ w - 1 := by have := hc.1; omega
    have hp : p = mask K d := (hc.2.1 K hK).symm
    simp [nodePasses, nodeOk, Tree.node, hd, hp]

theorem child_nodeOk {w d : Nat} {K : Key} {c : Tree} (hcc : Canonical w c) (hKc : K ∈ c.keys)
    (hdeep : ∀ d' p' cl cr, c = .branch d' p' cl cr → d < d') :
    nodeOk w K (some d) c.node = true := by
  cases c with
  | leaf k =>
    have : K = k := by simpa [Tree.keys] using hKc
    subst this
    simp [nodeOk, Tree.node]
  | branch d' p' cl cr =>
    have hlt := hdeep d' p' cl cr rfl
    have hd' : d' ≤ w - 1 := by have := hcc.1; omega
    have hp' : p' = mask K d' := (hcc.2.1 K hKc).symm
    simp [nodeOk, Tree.node, hlt, hd', hp']

theorem child_passes {w : Nat} {K : Key} {d : Nat} {p : Key} {l r : Tree}
    (hc : Canonical w (.branch d p l r)) (hK : K ∈ (Tree.branch d p l r).keys)
    (hp : p = mask K d) :
    nodePasses w K (.child d p (bit K d)) (cond (bit K d) r l).node = true := by
  have hd : d ≤ w - 1 := by have := hc.1; omega
  have hcmp : comparedChild w K d p (bit K d) = true := by
    simp [comparedChild, hd, hp]
  have hKc : K ∈ (cond (bit K d) r l).keys := by
    have hK' : K ∈ l.keys ∨ K ∈ r.keys := by simpa [Tree.keys] using hK
    cases hb : bit K d with
    | false =>
      rcases hK' with hl | hr
      · simpa using hl
      · have := hc.2.2.2.1 K hr; rw [hb] at this; exact Bool.noConfusion this
    | true =>
      rcases hK' with hl | hr
      · have := hc.2.2.1 K hl; rw [hb] at this; exact Bool.noConfusion this
      · simpa using hr
  have hcc : Canonical w (cond (bit K d) r l) := by
    cases bit K d
    · exact hc.2.2.2.2.1
    · exact hc.2.2.2.2.2
  have hdeep : ∀ d' p' cl cr, cond (bit K d) r l = .branch d' p' cl cr → d < d' := by
    intro d' p' cl cr hcd
    have hs : Sub (.branch d' p' cl cr) (cond (bit K d) r l) := hcd ▸ Sub.refl _
    exact depth_gt_in_side hc (bit K d) hs
  simp only [nodePasses, hcmp, Bool.not_true, Bool.false_or]
  exact child_nodeOk hcc hKc hdeep

theorem soundness {w : Nat} {K : Key} {t : Tree} (hc : Canonical w t) (hK : K ∈ t.keys) :
    nodePasses w K .top t.node = true ∧
    ∀ d p l r, Sub (.branch d p l r) t → p = mask K d →
      nodePasses w K (.child d p (bit K d)) (cond (bit K d) r l).node = true := by
  refine ⟨top_passes hc hK, ?_⟩
  intro d p l r hs hp
  exact child_passes (sub_canonical hs hc) (mem_of_sub_prefix hs rfl hc hK hp) hp

/-! Part (b): progress along the path of `K`. -/

theorem pathAt_succ {K : Key} {f : Pos → Node} {i : Nat} {pos : Pos}
    (h : pathAt K f (i + 1) = some pos) :
    ∃ pos0 d0 p0, pathAt K f i = some pos0 ∧ f pos0 = .branch d0 p0 ∧
      pos = .child d0 p0 (bit K d0) := by
  cases h0 : pathAt K f i with
  | none =>
    change (pathAt K f i).bind (step K f) = some pos at h
    rw [h0] at h; exact Option.noConfusion h
  | some pos0 =>
    change (pathAt K f i).bind (step K f) = some pos at h
    rw [h0] at h
    change step K f pos0 = some pos at h
    unfold step at h
    cases hf : f pos0 with
    | empty => rw [hf] at h; exact Option.noConfusion h
    | leaf k => rw [hf] at h; exact Option.noConfusion h
    | branch d0 p0 =>
      rw [hf] at h
      exact ⟨pos0, d0, p0, rfl, hf, (Option.some.inj h).symm⟩

theorem path_branch_depth {w : Nat} {K : Key} {f : Pos → Node}
    (hpass : ∀ i pos, pathAt K f i = some pos → nodePasses w K pos (f pos) = true) :
    ∀ i pos d p, pathAt K f i = some pos → f pos = .branch d p →
      i ≤ d ∧ d ≤ w - 1 ∧ p = mask K d := by
  intro i
  induction i with
  | zero =>
    intro pos d p hpos hf
    have hpos' : pos = .top := by simpa [pathAt] using hpos.symm
    subst hpos'
    have := hpass 0 .top hpos
    rw [hf] at this
    simp [nodePasses, nodeOk] at this
    exact ⟨Nat.zero_le _, this.1, this.2⟩
  | succ i ih =>
    intro pos d p hpos hf
    obtain ⟨pos0, d0, p0, h0, hf0, rfl⟩ := pathAt_succ hpos
    obtain ⟨hi, hd0, hp0⟩ := ih pos0 d0 p0 h0 hf0
    have hcmp : comparedChild w K d0 p0 (bit K d0) = true := by
      simp [comparedChild, hd0, hp0]
    have := hpass (i + 1) _ hpos
    rw [hf] at this
    simp only [nodePasses, nodeOk, hcmp, Bool.not_true, Bool.false_or, Bool.and_eq_true,
      decide_eq_true_eq] at this
    obtain ⟨⟨hlt, hd⟩, hp⟩ := this
    exact ⟨by omega, hd, hp⟩

theorem path_compared {w : Nat} {K : Key} {f : Pos → Node}
    (hpass : ∀ i pos, pathAt K f i = some pos → nodePasses w K pos (f pos) = true)
    {i : Nat} {pos : Pos} (hpos : pathAt K f i = some pos) :
    pos = .top ∨ ∃ d, pos = .child d (mask K d) (bit K d) ∧ comparedChild w K d (mask K d) (bit K d) = true := by
  cases i with
  | zero => left; simpa [pathAt] using hpos.symm
  | succ i =>
    right
    obtain ⟨pos0, d0, p0, h0, hf0, rfl⟩ := pathAt_succ hpos
    obtain ⟨_, hd0, hp0⟩ := path_branch_depth hpass i pos0 d0 p0 h0 hf0
    subst hp0
    exact ⟨d0, rfl, by simp [comparedChild, hd0]⟩

def BranchAt (K : Key) (f : Pos → Node) (j : Nat) : Prop :=
  ∃ pos d p, pathAt K f j = some pos ∧ f pos = .branch d p

theorem path_some_of_branches {K : Key} {f : Pos → Node} :
    ∀ n, (∀ j, j < n → BranchAt K f j) → ∃ pos, pathAt K f n = some pos := by
  intro n
  induction n with
  | zero => intro _; exact ⟨.top, rfl⟩
  | succ n _ =>
    intro h
    obtain ⟨pos, d, p, hpos, hf⟩ := h n (Nat.lt_succ_self n)
    refine ⟨.child d p (bit K d), ?_⟩
    simp [pathAt, hpos, step, hf]

theorem branches_or_stop (K : Key) (f : Pos → Node) :
    ∀ n, (∀ j, j < n → BranchAt K f j) ∨
      ∃ m, m < n ∧ (∀ j, j < m → BranchAt K f j) ∧ ¬ BranchAt K f m := by
  intro n
  induction n with
  | zero => left; intro j hj; exact absurd hj (Nat.not_lt_zero j)
  | succ n ih =>
    rcases ih with hall | ⟨m, hm, hpre, hnot⟩
    · by_cases hb : BranchAt K f n
      · left
        intro j hj
        rcases Nat.lt_or_eq_of_le (Nat.le_of_lt_succ hj) with hlt | heq
        · exact hall j hlt
        · exact heq ▸ hb
      · right; exact ⟨n, Nat.lt_succ_self n, hall, hb⟩
    · right; exact ⟨m, Nat.lt_succ_of_lt hm, hpre, hnot⟩

theorem progress {w : Nat} (hw : 0 < w) (K : Key) (f : Pos → Node)
    (hpass : ∀ i pos, pathAt K f i = some pos → nodePasses w K pos (f pos) = true) :
    ∃ n, n ≤ w ∧ (∀ i, i < n → ∃ pos d p, pathAt K f i = some pos ∧ f pos = .branch d p) ∧
      ∃ pos, pathAt K f n = some pos ∧ f pos = .leaf K := by
  rcases branches_or_stop K f (w + 1) with hall | ⟨m, hm, hpre, hnot⟩
  · exfalso
    obtain ⟨pos, d, p, hpos, hf⟩ := hall w (Nat.lt_succ_self w)
    have := (path_branch_depth hpass w pos d p hpos hf).2.1
    have := (path_branch_depth hpass w pos d p hpos hf).1
    omega
  · refine ⟨m, Nat.le_of_lt_succ hm, hpre, ?_⟩
    obtain ⟨pos, hpos⟩ := path_some_of_branches m hpre
    refine ⟨pos, hpos, ?_⟩
    have hp := hpass m pos hpos
    cases hf : f pos with
    | branch d p => exact absurd ⟨pos, d, p, hpos, hf⟩ hnot
    | empty =>
      rw [hf] at hp
      rcases path_compared hpass hpos with htop | ⟨d, rfl, hcmp⟩
      · subst htop; simp [nodePasses, nodeOk] at hp
      · simp [nodePasses, nodeOk, hcmp] at hp
    | leaf k =>
      rw [hf] at hp
      rcases path_compared hpass hpos with htop | ⟨d, rfl, hcmp⟩
      · subst htop; simp [nodePasses, nodeOk] at hp; rw [hp]
      · simp [nodePasses, nodeOk, hcmp] at hp; rw [hp]

/-! Part (c): refusal. -/

theorem fails_of_member {w : Nat} {present : List Key} {K : Key} {r : Result}
    (hK : K ∈ present) (h : resultPassesFor w K r = false) : resultPasses w present r = false := by
  cases hr : resultPasses w present r with
  | false => rfl
  | true =>
    unfold resultPasses at hr
    rw [List.all_eq_true] at hr
    have := hr K hK
    rw [h] at this
    exact Bool.noConfusion this

theorem compared_node_fails {w : Nat} {K : Key} {pos : Pos} (hpos : Compared w K pos)
    {n : Node} (hn : nodeOk w K none n = false) : nodePasses w K pos n = false := by
  rcases hpos with rfl | ⟨d, hd, rfl⟩
  · simpa [nodePasses] using hn
  · have hcmp : comparedChild w K d (mask K d) (bit K d) = true := by simp [comparedChild, hd]
    simp only [nodePasses, hcmp, Bool.not_true, Bool.false_or]
    cases n with
    | empty => rfl
    | leaf k => simpa [nodeOk] using hn
    | branch d' p =>
      simp only [nodeOk, Bool.true_and] at hn
      simp only [nodeOk, hn, Bool.and_false, Bool.and_assoc]

theorem refusal {w : Nat} {present : List Key} {K : Key} (hK : K ∈ present) :
    resultPasses w present (.root true) = false ∧
    (∀ pos, Compared w K pos →
      (∀ k, k ≠ K → resultPasses w present (.atPos pos (.leaf k)) = false) ∧
      (∀ d' p, p ≠ mask K d' → resultPasses w present (.atPos pos (.branch d' p)) = false) ∧
      resultPasses w present (.atPos pos .empty) = false ∧
      (∀ d' p, w - 1 < d' → resultPasses w present (.atPos pos (.branch d' p)) = false)) ∧
    (∀ d, d ≤ w - 1 → ∀ d' p, d' ≤ d →
      resultPasses w present (.atPos (.child d (mask K d) (bit K d)) (.branch d' p)) = false) := by
  refine ⟨fails_of_member hK rfl, ?_, ?_⟩
  · intro pos hpos
    refine ⟨?_, ?_, ?_, ?_⟩
    · intro k hk
      exact fails_of_member hK (compared_node_fails hpos (by simp [nodeOk, hk]))
    · intro d' p hp
      exact fails_of_member hK (compared_node_fails hpos (by simp [nodeOk, hp]))
    · exact fails_of_member hK (compared_node_fails hpos rfl)
    · intro d' p hd'
      have : ¬ d' ≤ w - 1 := by omega
      exact fails_of_member hK (compared_node_fails hpos (by simp [nodeOk, this]))
  · intro d hd d' p hle
    have hcmp : comparedChild w K d (mask K d) (bit K d) = true := by simp [comparedChild, hd]
    have hnlt : ¬ d < d' := by omega
    exact fails_of_member hK (by simp [resultPassesFor, nodePasses, nodeOk, hcmp, hnlt])

/-! Part (d): point of the failed check. -/

theorem failsFirst_nil {w : Nat} {present : List Key} : ¬ FailsFirst w present [] := by
  rintro ⟨pre, r, post, h, _, _⟩
  cases pre <;> simp at h

theorem unavailableFirst_nil {w : Nat} {present : List Key} : ¬ UnavailableFirst w present [] := by
  rintro ⟨pre, post, h, _⟩
  cases pre <;> simp at h

/-- A sequence that starts with a passing obtain or a consume decides as its
remainder. -/
theorem failsFirst_cons_skip {w : Nat} {present : List Key} {e : Event} {es : List Event}
    (he : e ≠ .unavailable) (hskip : ∀ r, e = .obtain r → resultPasses w present r = true) :
    FailsFirst w present (e :: es) ↔ FailsFirst w present es := by
  constructor
  · rintro ⟨pre, r, post, h, hr, hu⟩
    cases pre with
    | nil =>
      simp at h
      rw [hskip r h.1] at hr; exact absurd hr (by decide)
    | cons x pre =>
      simp at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨pre, r, post, rfl, hr, fun hm => hu (List.mem_cons_of_mem _ hm)⟩
  · rintro ⟨pre, r, post, rfl, hr, hu⟩
    refine ⟨e :: pre, r, post, rfl, hr, ?_⟩
    intro hm
    rcases List.mem_cons.mp hm with h | h
    · exact he h.symm
    · exact hu h

theorem unavailableFirst_cons_skip {w : Nat} {present : List Key} {e : Event} {es : List Event}
    (he : e ≠ .unavailable) (hskip : ∀ r, e = .obtain r → resultPasses w present r = true) :
    UnavailableFirst w present (e :: es) ↔ UnavailableFirst w present es := by
  constructor
  · rintro ⟨pre, post, h, hr⟩
    cases pre with
    | nil => simp at h; exact absurd h.1 he
    | cons x pre =>
      simp at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨pre, post, rfl, fun r hm => hr r (List.mem_cons_of_mem _ hm)⟩
  · rintro ⟨pre, post, rfl, hr⟩
    refine ⟨e :: pre, post, rfl, ?_⟩
    intro r hm
    rcases List.mem_cons.mp hm with h | h
    · exact hskip r h.symm
    · exact hr r h

theorem finding_characterization (w : Nat) (present : List Key) :
    ∀ es : List Event,
      (firstFinding w present es = some .failedCheck ↔ FailsFirst w present es) ∧
      (firstFinding w present es = some .unavailableRead ↔ UnavailableFirst w present es) ∧
      (firstFinding w present es = none ↔
        ¬ FailsFirst w present es ∧ ¬ UnavailableFirst w present es) := by
  intro es
  induction es with
  | nil =>
    simp [firstFinding, failsFirst_nil, unavailableFirst_nil]
  | cons e es ih =>
    cases e with
    | consume =>
      have h1 := failsFirst_cons_skip (w := w) (present := present) (es := es)
        (e := .consume) (by decide) (fun r h => Event.noConfusion h)
      have h2 := unavailableFirst_cons_skip (w := w) (present := present) (es := es)
        (e := .consume) (by decide) (fun r h => Event.noConfusion h)
      simp only [firstFinding, h1, h2]
      exact ih
    | unavailable =>
      have hf : ¬ FailsFirst w present (.unavailable :: es) := by
        rintro ⟨pre, r, post, h, _, hu⟩
        cases pre with
        | nil => simp at h
        | cons x pre => simp at h; exact hu (h.1 ▸ List.mem_cons_self _ _)
      have hu : UnavailableFirst w present (.unavailable :: es) :=
        ⟨[], es, rfl, fun r hm => absurd hm (List.not_mem_nil _)⟩
      simp [firstFinding, hf, hu]
    | obtain r =>
      cases hr : resultPasses w present r with
      | true =>
        have h1 := failsFirst_cons_skip (w := w) (present := present) (es := es)
          (e := .obtain r) (fun h => Event.noConfusion h) (fun r' h => by cases h; exact hr)
        have h2 := unavailableFirst_cons_skip (w := w) (present := present) (es := es)
          (e := .obtain r) (fun h => Event.noConfusion h) (fun r' h => by cases h; exact hr)
        simp only [firstFinding, hr, if_true, h1, h2]
        exact ih
      | false =>
        have hf : FailsFirst w present (.obtain r :: es) :=
          ⟨[], r, es, rfl, hr, List.not_mem_nil _⟩
        have hu : ¬ UnavailableFirst w present (.obtain r :: es) := by
          rintro ⟨pre, post, h, hp⟩
          cases pre with
          | nil => simp at h
          | cons x pre =>
            simp at h
            have := hp r (h.1 ▸ List.mem_cons_self _ _)
            rw [hr] at this; exact Bool.noConfusion this
        simp [firstFinding, hr, hf, hu]

theorem finding_drop_consumes (w : Nat) (present : List Key) :
    ∀ es : List Event,
      firstFinding w present (es.filter (fun e => !e.isConsume)) = firstFinding w present es := by
  intro es
  induction es with
  | nil => rfl
  | cons e es ih =>
    cases e with
    | consume => exact ih
    | unavailable => rfl
    | obtain r =>
      change firstFinding w present (Event.obtain r :: List.filter (fun e => !e.isConsume) es) = _
      simp only [firstFinding, ih]

/-- The registered contract at the key width 288 (depth bound 287). -/
theorem root_path_comparison_contract :
    (∀ (t : Tree) (K : Key), Canonical 288 t → K ∈ t.keys →
      nodePasses 288 K .top t.node = true ∧
      ∀ d p l r, Sub (.branch d p l r) t → p = mask K d →
        nodePasses 288 K (.child d p (bit K d)) (cond (bit K d) r l).node = true) ∧
    (∀ (K : Key) (f : Pos → Node),
      (∀ i pos, pathAt K f i = some pos → nodePasses 288 K pos (f pos) = true) →
      ∃ n, n ≤ 288 ∧ (∀ i, i < n → ∃ pos d p, pathAt K f i = some pos ∧ f pos = .branch d p) ∧
        ∃ pos, pathAt K f n = some pos ∧ f pos = .leaf K) ∧
    (∀ (present : List Key) (K : Key), K ∈ present →
      resultPasses 288 present (.root true) = false ∧
      (∀ pos, Compared 288 K pos →
        (∀ k, k ≠ K → resultPasses 288 present (.atPos pos (.leaf k)) = false) ∧
        (∀ d' p, p ≠ mask K d' → resultPasses 288 present (.atPos pos (.branch d' p)) = false) ∧
        resultPasses 288 present (.atPos pos .empty) = false ∧
        (∀ d' p, 287 < d' → resultPasses 288 present (.atPos pos (.branch d' p)) = false)) ∧
      (∀ d, d ≤ 287 → ∀ d' p, d' ≤ d →
        resultPasses 288 present (.atPos (.child d (mask K d) (bit K d)) (.branch d' p)) = false)) ∧
    (∀ (present : List Key) (es : List Event),
      (firstFinding 288 present es = some .failedCheck ↔ FailsFirst 288 present es) ∧
      (firstFinding 288 present es = some .unavailableRead ↔ UnavailableFirst 288 present es) ∧
      (firstFinding 288 present es = none ↔
        ¬ FailsFirst 288 present es ∧ ¬ UnavailableFirst 288 present es) ∧
      firstFinding 288 present (es.filter (fun e => !e.isConsume)) = firstFinding 288 present es) :=
  ⟨fun _ _ hc hK => soundness hc hK,
   fun K f hpass => progress (by decide) K f hpass,
   fun _ _ hK => refusal hK,
   fun present es =>
     let h := finding_characterization 288 present es
     ⟨h.1, h.2.1, h.2.2, finding_drop_consumes 288 present es⟩⟩

/-! Case examples (unregistered) at the reduced key width 10: the depth bound
287 of a case reads as 9. Each expected value is the literal case outcome. -/

namespace Examples

def kA : Key := [true, false, true, true, false, false, true, false, true, true]
/-- Shares bits 0..6 with `kA`; differs at bit 7. -/
def kB : Key := [true, false, true, true, false, false, true, true, true, true]
/-- Differs from `kA` at bit 3. -/
def kC : Key := [true, false, true, false, false, false, true, false, true, true]
/-- Differs from `kA` at bit 0. -/
def kX : Key := [false, false, true, true, false, false, true, false, true, true]
/-- `kA` with bit 8 flipped. -/
def kE : Key := [true, false, true, true, false, false, true, false, false, true]
/-- `kE` with bit 3 flipped. -/
def kF : Key := [true, false, true, false, false, false, true, false, false, true]

def topB5 : Event := .obtain (.atPos .top (.branch 5 (mask kA 5)))
def childA5 : Pos := .child 5 (mask kA 5) (bit kA 5)

-- N01
example : firstFinding 10 [kA] [.obtain (.root false)] = none := by decide
-- N02
example : firstFinding 10 [kA] [.obtain (.atPos .top (.leaf kA))] = none := by decide
-- N03
example : firstFinding 10 [kA] [topB5] = none := by decide
-- N04
example : firstFinding 10 [kA] [topB5, .obtain (.atPos childA5 (.leaf kA))] = none := by decide
-- N05
example : firstFinding 10 [kA] [topB5, .obtain (.atPos childA5 (.branch 9 (mask kA 9)))] = none := by
  decide
-- N06
example :
    firstFinding 10 [kA] [topB5, .obtain (.atPos (.child 5 (mask kA 5) (!bit kA 5)) (.leaf kX))] = none ∧
    firstFinding 10 [kA] [.obtain (.atPos (.child 5 (mask kX 5) (bit kA 5)) (.leaf kX))] = none := by
  decide
-- N07
example : firstFinding 10 [kA] [.obtain (.noPos (.leaf kX))] = none := by decide
-- N08
example : firstFinding 10 [kA] [.obtain (.atPos .top (.leaf kA))] = none := by decide
-- N12
example :
    firstFinding 10 [kA] [.obtain (.atPos .top (.branch 3 (mask kA 3))),
      .obtain (.atPos (.child 3 (mask kA 3) (bit kA 3)) (.branch 5 (mask kA 5))),
      .obtain (.atPos childA5 (.leaf kX))] = some .failedCheck ∧
    firstFinding 10 [kC] [.obtain (.atPos .top (.branch 3 (mask kA 3))),
      .obtain (.atPos (.child 3 (mask kA 3) (bit kA 3)) (.branch 5 (mask kA 5))),
      .obtain (.atPos childA5 (.leaf kX))] = none := by
  decide
-- N14
example :
    firstFinding 10 [kA] [.obtain (.noPos (.branch 10 (mask kA 10))),
      .obtain (.atPos (.child 10 (mask kA 10) (bit kA 10)) (.leaf kX))] = none := by
  decide
-- N15
example : firstFinding 10 [kA] [.unavailable, .obtain (.atPos .top (.leaf kX))] = some .unavailableRead := by
  decide
-- N20
example : firstFinding 10 [kA] [.obtain (.root true)] = some .failedCheck := by decide
-- N21
example : firstFinding 10 [kA] [.obtain (.atPos .top (.leaf kX))] = some .failedCheck := by decide
-- N22
example : firstFinding 10 [kA] [.obtain (.atPos .top (.branch 5 (mask kX 5)))] = some .failedCheck := by
  decide
-- N23
example : firstFinding 10 [kA] [.obtain (.atPos .top .empty)] = some .failedCheck := by decide
-- N24
example : firstFinding 10 [kA] [topB5, .obtain (.atPos childA5 (.leaf kX))] = some .failedCheck := by
  decide
-- N25
example :
    firstFinding 10 [kA] [topB5, .obtain (.atPos childA5 (.branch 9 (mask kX 9)))] = some .failedCheck := by
  decide
-- N26
example :
    firstFinding 10 [kA] [topB5, .obtain (.atPos childA5 (.branch 5 (mask kA 5)))] = some .failedCheck := by
  decide
-- N27
example :
    firstFinding 10 [kA] [.obtain (.atPos .top (.branch 10 (mask kA 10)))] = some .failedCheck ∧
    firstFinding 10 [kA] [topB5, .obtain (.atPos childA5 (.branch 10 (mask kA 10)))] = some .failedCheck := by
  decide
-- N28
example : firstFinding 10 [kA, kB] [.obtain (.atPos .top (.leaf kA))] = some .failedCheck := by decide
-- N29
example :
    firstFinding 10 [kA, kB] [.obtain (.atPos .top (.branch 9 (mask kA 9)))] = some .failedCheck := by
  decide
-- N30
example : firstFinding 10 [kA] [.obtain (.atPos .top (.leaf kX)), .consume] = some .failedCheck := by
  decide
-- N31
example : firstFinding 10 [kA] [.obtain (.atPos .top (.leaf kX)), .unavailable] = some .failedCheck := by
  decide
-- N32
example : firstFinding 10 [kA] [.consume, .obtain (.atPos .top (.leaf kX))] = some .failedCheck := by
  decide
-- N33
example : firstFinding 10 [kA] [topB5, .consume, .obtain (.atPos childA5 (.leaf kX))] = some .failedCheck := by
  decide
-- N34
example :
    firstFinding 10 [kA] [.obtain (.noPos (.branch 5 (mask kA 5))),
      .obtain (.atPos childA5 (.leaf kX))] = some .failedCheck := by
  decide
-- N35
example : firstFinding 10 [kA] [topB5, .obtain (.atPos childA5 .empty)] = some .failedCheck := by decide
-- N46
example :
    firstFinding 10 [kA] [.obtain (.noPos (.leaf kA)), .obtain (.atPos .top (.leaf kX))] = some .failedCheck ∧
    firstFinding 10 [kA] [.obtain (.noPos (.leaf kA)), .obtain (.noPos (.leaf kX)), .consume] = none := by
  decide
-- N47
def mapWithoutA : Tree := .branch 3 (mask kE 3) (.leaf kF) (.leaf kE)
example :
    Canonical 10 mapWithoutA ∧ kA ∉ mapWithoutA.keys ∧
    firstFinding 10 [kA] ((mapWithoutA.pathResults kA .top).map .obtain) = some .failedCheck := by
  decide

end Examples

end RubinFormal.RootPathComparisonV1
