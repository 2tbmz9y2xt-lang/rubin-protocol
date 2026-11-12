import Std

/-!
Bounded model of the proposed rule on the single insertion of an outpoint and of the
proposed failed check for a parent-view entry or leaf at an inserted outpoint
(rubin-spec `RUBIN_CONSENSUS_STATE_MACHINE.md` Sections 2.4 and 2.5 at
139b79cb162928b0a0ab7493fe4f4ea7932ae822, with the proposed sentences of Linear RUB-1920).

Part one applies a chain of abstract blocks from the empty set of outpoints. A core stands
for the fields of `TxCoreBytes` that the rule cites, and equal cores stand for equal
`TxCoreBytes`; identifiers come from an arbitrary function `tid` on cores, so hashing is not
represented. Part two decides the failed check over a finite sequence of read events; the
events carry how a result comes to identify a leaf. The model does not represent bytes, the
transaction encoding, store reads, the derivation of `Root(U_candidate)`, the rules that the
proposed rule does not cite, or any client behavior. It is a model property with no bridge
to Go or Rust code.
-/
namespace RubinFormal.OutpointInsertionV1

/-! ## Part one: types -/

/-- An outpoint: (identifier, output index). -/
abbrev Outpoint := Nat × Nat

/-- The fields of `TxCoreBytes` that the rule cites. `outputs` holds the spendable flag of
each output in `vout` order. Equal cores stand for equal `TxCoreBytes`. -/
structure Core where
  nonce : Nat
  inputs : List Outpoint
  locktime : Nat
  outputs : List Bool
  deriving DecidableEq

/-- A transaction: its core and `cbRest`, which stands for every condition of
`is_coinbase_tx` other than `tx_nonce = 0`. -/
structure Tx where
  core : Core
  cbRest : Bool
  deriving DecidableEq

/-- Transactions in block order, index 0 first. -/
abbrev Block := List Tx

/-- Blocks in chain order; the block at list index `h` has height `h`. -/
abbrev Chain := List Block

/-- The present outpoints; presence is membership, entry contents are not represented. -/
abbrev State := List Outpoint

/-- `is_coinbase_tx`: nonce 0 and every other condition (`cbRest`). -/
def isCoinbaseTx (t : Tx) : Bool := decide (t.core.nonce = 0) && t.cbRest

/-- The keys `(id, j)` of the spendable outputs, where `j` counts every output from `j`. -/
def keysFrom (id : Nat) : Nat → List Bool → List Outpoint
  | _, [] => []
  | j, true :: bs => (id, j) :: keysFrom id (j + 1) bs
  | j, false :: bs => keysFrom id (j + 1) bs

/-- The keys at which the spendable outputs of a core are inserted, ascending (E1). -/
def spendKeys (tid : Core → Nat) (c : Core) : List Outpoint := keysFrom (tid c) 0 c.outputs

/-- An insertion, with the presence of the outpoint before it, or a removal. -/
inductive Effect where
  | ins (op : Outpoint) (wasPresent : Bool)
  | rem (op : Outpoint)
  deriving DecidableEq

/-- The outpoint of an effect. -/
def Effect.op : Effect → Outpoint
  | .ins op _ => op
  | .rem op => op

/-- The result of a block; `noResult` is the explicit value for "no result is defined". -/
inductive BlockResult where
  | valid (s : State)
  | invalid
  | noResult
  deriving DecidableEq

/-- An applied transaction: height, index in its block and core. -/
structure Applied where
  height : Nat
  index : Nat
  core : Core
  deriving DecidableEq

/-! ## Part one: baseline application -/

/-- Inserts the keys in order; each records its presence in the current state, then is
present. Inserting a present outpoint leaves it present (the assignment form). -/
def insertKeys : State → List Outpoint → State × List Effect
  | s, [] => (s, [])
  | s, op :: ks =>
    let r := insertKeys (if op ∈ s then s else s ++ [op]) ks
    (r.1, .ins op (decide (op ∈ s)) :: r.2)

/-- The state with every listed input absent. -/
def removeAll (s : State) (ops : List Outpoint) : State := s.filter (fun x => !decide (x ∈ ops))

/-- The checks of a transaction at an index above 0: nonce not 0, at least one input, and
every input present (`R1`). -/
def spendOk (s : State) (c : Core) : Bool :=
  !decide (c.nonce = 0) && !c.inputs.isEmpty && c.inputs.all (fun op => decide (op ∈ s))

/-- Step (4): the transactions after the coinbase, from index `i`, in index order. -/
def runTxs (tid : Core → Nat) (h : Nat) :
    Nat → State → List Tx → BlockResult × List Applied × List Effect
  | _, s, [] => (.valid s, [], [])
  | i, s, t :: rest =>
    if spendOk s t.core then
      let r := insertKeys (removeAll s t.core.inputs) (spendKeys tid t.core)
      let q := runTxs tid h (i + 1) r.1 rest
      (q.1, ⟨h, i, t.core⟩ :: q.2.1, t.core.inputs.map .rem ++ r.2 ++ q.2.2)
    else (.invalid, [], [])

/-- Validation of a block at height `h` from state `s`: empty block, preflight,
`ApplyCoinbase` with its locktime check, then the later transactions. -/
def runBlock (tid : Core → Nat) (h : Nat) (s : State) :
    Block → BlockResult × List Applied × List Effect
  | [] => (.invalid, [], [])
  | cb :: rest =>
    if isCoinbaseTx cb && !rest.any isCoinbaseTx then
      if cb.core.locktime = h then
        let r := insertKeys s (spendKeys tid cb.core)
        let q := runTxs tid h 1 r.1 rest
        (q.1, ⟨h, 0, cb.core⟩ :: q.2.1, r.2 ++ q.2.2)
      else (.invalid, [], [])
    else (.invalid, [], [])

/-- Blocks from height `h` and state `s`: one result per block up to and including the first
result that is not `valid`. -/
def runFrom (tid : Core → Nat) : Nat → State → Chain → List BlockResult × List Applied × List Effect
  | _, _, [] => ([], [], [])
  | h, s, b :: rest =>
    let r := runBlock tid h s b
    match r.1 with
    | .valid s' =>
      let q := runFrom tid (h + 1) s' rest
      (.valid s' :: q.1, r.2.1 ++ q.2.1, r.2.2 ++ q.2.2)
    | _ => ([r.1], r.2.1, r.2.2)

/-- The baseline run from the empty state before height 0: results, applied list, effects. -/
def runBase (tid : Core → Nat) (chain : Chain) : List BlockResult × List Applied × List Effect :=
  runFrom tid 0 [] chain

/-! ## Part one: the rule -/

/-- Any two entries with equal identifiers have equal cores. -/
def Consistent (tid : Core → Nat) (L : List Applied) : Prop :=
  ∀ a ∈ L, ∀ b ∈ L, tid a.core = tid b.core → a.core = b.core

/-- The condition of E2 on the applied list of the baseline run. -/
def Premise (tid : Core → Nat) (chain : Chain) : Prop := Consistent tid (runBase tid chain).2.1

/-- The height of the first entry whose identifier equals that of an earlier entry (in
`seen` or earlier in the list) and whose core differs from that entry's core. -/
def breakAt (tid : Core → Nat) : List Applied → List Applied → Option Nat
  | _, [] => none
  | seen, a :: rest =>
    if seen.any (fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core)) then
      some a.height
    else breakAt tid (seen ++ [a]) rest

/-- The height of the block of the first application that breaks the premise. -/
def firstBreak (tid : Core → Nat) (chain : Chain) : Option Nat :=
  breakAt tid [] (runBase tid chain).2.1

/-- The baseline results, except that from the block of the first premise break on, every
block of the chain has `noResult`. -/
def applyChain (tid : Core → Nat) (chain : Chain) : List BlockResult :=
  match firstBreak tid chain with
  | none => (runBase tid chain).1
  | some k => (runBase tid chain).1.take k ++ List.replicate (chain.length - k) .noResult

/-- The outpoints of the insertion effects, in order. -/
def insOps (E : List Effect) : List Outpoint :=
  E.filterMap (fun e => match e with
    | .ins op _ => some op
    | .rem _ => none)

/-! ## Part two: types and the rule -/

/-- The derivation, or the operation that includes input resolution. -/
inductive Op where
  | derivation
  | resolution
  deriving DecidableEq

/-- A keyed lookup, or a read that establishes presence or definitive absence for several
outpoints. -/
inductive ReadKind where
  | keyed
  | multi
  deriving DecidableEq

/-- A read event of operation `who` for outpoint `op`. -/
inductive Event where
  /-- A complete present entry from the exact selected parent-branch view; `crossRowOk` is
  whether it satisfies every relation of the cross-row consistency check. -/
  | parentEntry (who : Op) (op : Outpoint) (how : ReadKind) (crossRowOk : Bool)
  /-- A result from that view that identifies a leaf for an entry of `op`, holding `held`. -/
  | parentLeaf (who : Op) (op : Outpoint) (held : Nat)
  /-- A definitive absence from that view. -/
  | parentAbsent (who : Op) (op : Outpoint)
  /-- An entry from the private-candidate view. -/
  | candidateEntry (who : Op) (op : Outpoint)
  /-- An unavailable required read. -/
  | unavailable
  /-- A consumption. -/
  | consume (who : Op)
  deriving DecidableEq

inductive Finding where
  | failedCheck
  | unavailableRead
  deriving DecidableEq

/-- At a height above 0, `op` is inserted by the block and was not resolved as a present
entry of `U_parent`. -/
def inserted (h : Nat) (ins resolved : List Outpoint) (op : Outpoint) : Bool :=
  decide (0 < h) && decide (op ∈ ins) && !decide (op ∈ resolved)

/-- The failed check of E4: a parent-view entry or leaf obtained by the derivation at an
inserted outpoint. -/
def failsE4 (h : Nat) (ins resolved : List Outpoint) : Event → Bool
  | .parentEntry .derivation op _ _ => inserted h ins resolved op
  | .parentLeaf .derivation op _ => inserted h ins resolved op
  | _ => false

/-- The first event that is unavailable or fails E4 decides; a consumption decides nothing.
Of the failed checks of the store this represents only the one that E4 adds: no other failed
check is represented, `crossRowOk` enters no finding, and `none` means only that neither E4
nor an unavailable read gives a finding. Where an unrepresented check fails, this value need
not be the outcome that the specification gives. -/
def insertionFinding (h : Nat) (ins resolved : List Outpoint) : List Event → Option Finding
  | [] => none
  | e :: es =>
    if e = .unavailable then some .unavailableRead
    else if failsE4 h ins resolved e then some .failedCheck
    else insertionFinding h ins resolved es

/-- The outcome without E4, as far as the model represents it: only an unavailable read.
No failed check of the store is represented, so where one fails this value need not be the
outcome that the specification gives. -/
def baselineFinding (es : List Event) : Option Finding :=
  if Event.unavailable ∈ es then some .unavailableRead else none

inductive StoreOutcome where
  | finding (f : Finding)
  | noFinding
  | noOutcome
  deriving DecidableEq

/-- A block whose result is `noResult` has no outcome; otherwise the finding decides. -/
def storeOutcome (r : BlockResult) (h : Nat) (ins resolved : List Outpoint)
    (es : List Event) : StoreOutcome :=
  match r with
  | .noResult => .noOutcome
  | _ =>
    match insertionFinding h ins resolved es with
    | some f => .finding f
    | none => .noFinding

/-- Whether an event is a consumption. -/
def isConsume : Event → Bool
  | .consume _ => true
  | _ => false

/-- The event with `how`, `crossRowOk` and `held` replaced by fixed values. -/
def forget : Event → Event
  | .parentEntry w op _ _ => .parentEntry w op .keyed true
  | .parentLeaf w op _ => .parentLeaf w op 0
  | e => e

/-- Some event fails E4 with no unavailable event before it. -/
def FailFirst (h : Nat) (ins resolved : List Outpoint) (es : List Event) : Prop :=
  ∃ pre e post, es = pre ++ e :: post ∧ failsE4 h ins resolved e = true ∧
    Event.unavailable ∉ pre

/-- Some unavailable event has no event that fails E4 before it. -/
def UnavFirst (h : Nat) (ins resolved : List Outpoint) (es : List Event) : Prop :=
  ∃ pre post, es = pre ++ Event.unavailable :: post ∧
    ∀ e ∈ pre, failsE4 h ins resolved e = false

/-! ## Part one: lemmas for parts (a) and (b) -/

theorem keysFrom_mem {id j : Nat} {bs : List Bool} {k : Outpoint} (hk : k ∈ keysFrom id j bs) :
    k.1 = id ∧ j ≤ k.2 := by
  induction bs generalizing j with
  | nil => simp [keysFrom] at hk
  | cons b bs ih =>
    cases b with
    | true =>
      simp only [keysFrom, List.mem_cons] at hk
      rcases hk with rfl | hk
      · exact ⟨rfl, Nat.le_refl _⟩
      · have := ih hk; exact ⟨this.1, Nat.le_of_succ_le this.2⟩
    | false =>
      simp only [keysFrom] at hk
      have := ih hk; exact ⟨this.1, Nat.le_of_succ_le this.2⟩

theorem keysFrom_nodup (id j : Nat) (bs : List Bool) : (keysFrom id j bs).Pairwise (· ≠ ·) := by
  induction bs generalizing j with
  | nil => exact List.Pairwise.nil
  | cons b bs ih =>
    cases b with
    | true =>
      simp only [keysFrom]
      refine List.Pairwise.cons ?_ (ih (j + 1))
      intro k hk heq
      have := (keysFrom_mem hk).2
      rw [← heq] at this
      exact Nat.not_succ_le_self j this
    | false => simp only [keysFrom]; exact ih (j + 1)

/-- Inserting fresh, pairwise distinct keys appends them, each with `wasPresent` false. -/
theorem insertKeys_fresh : ∀ (s : State) (ks : List Outpoint), (∀ k ∈ ks, k ∉ s) →
    ks.Pairwise (· ≠ ·) → insertKeys s ks = (s ++ ks, ks.map (fun k => Effect.ins k false))
  | s, [], _, _ => by simp [insertKeys]
  | s, op :: ks, hf, hnd => by
    have hop : op ∉ s := hf op (List.mem_cons_self _ _)
    have hnd' := List.pairwise_cons.1 hnd
    have ih := insertKeys_fresh (s ++ [op]) ks (by
      intro k hk hks
      rcases List.mem_append.1 hks with h1 | h1
      · exact hf k (List.mem_cons_of_mem _ hk) h1
      · exact hnd'.1 k hk (List.mem_singleton.1 h1).symm) hnd'.2
    simp [insertKeys, hop, ih]

theorem mem_removeAll {s ops : List Outpoint} {x : Outpoint} :
    x ∈ removeAll s ops ↔ x ∈ s ∧ x ∉ ops := by
  simp [removeAll, List.mem_filter]

theorem spendOk_iff (s : State) (c : Core) :
    spendOk s c = true ↔ c.nonce ≠ 0 ∧ c.inputs ≠ [] ∧ ∀ op ∈ c.inputs, op ∈ s := by
  cases hi : c.inputs <;> simp [spendOk, hi, List.all_eq_true]

/-- The identifiers of an applied list. -/
def tids (tid : Core → Nat) (A : List Applied) : List Nat := A.map (fun a => tid a.core)

theorem tids_append (tid : Core → Nat) (A : List Applied) (a : Applied) :
    tids tid (A ++ [a]) = tids tid A ++ [tid a.core] := by simp [tids]

theorem mem_tids {tid : Core → Nat} {A : List Applied} {a : Applied} (ha : a ∈ A) :
    tid a.core ∈ tids tid A := List.mem_map_of_mem (fun a => tid a.core) ha

/-- An earlier effect does not have the outpoint of a later insertion. -/
def EffRel (x y : Effect) : Prop := ∀ op w, y = .ins op w → x.op ≠ op

/-- What the run keeps about its applied list and effects while that list satisfies
`Consistent` (`runFrom_good`). -/
structure Good (tid : Core → Nat) (A : List Applied) (E : List Effect) : Prop where
  nodup : (tids tid A).Pairwise (· ≠ ·)
  old : ∀ e ∈ E, e.op.1 ∈ tids tid A
  insFalse : ∀ op w, Effect.ins op w ∈ E → w = false
  rel : E.Pairwise EffRel

/-- What the run keeps about the current state while its applied list satisfies `Consistent`;
`bound` exceeds every applied coinbase locktime. -/
structure SInv (tid : Core → Nat) (A : List Applied) (s : State) (bound : Nat) : Prop where
  present : ∀ op ∈ s, op.1 ∈ tids tid A
  spent : ∀ a ∈ A, a.core.nonce ≠ 0 → ∀ op ∈ a.core.inputs, op ∉ s ∧ op.1 ∈ tids tid A
  cb : ∀ a ∈ A, a.core.nonce = 0 → a.core.locktime < bound

theorem pairwise_noIns : ∀ (P : List Effect), (∀ e ∈ P, ∀ op w, e ≠ .ins op w) → P.Pairwise EffRel
  | [], _ => List.Pairwise.nil
  | x :: P, hP => by
    refine List.Pairwise.cons ?_ (pairwise_noIns P (fun e he => hP e (List.mem_cons_of_mem _ he)))
    intro y hy op w hyeq
    exact absurd hyeq (hP y (List.mem_cons_of_mem _ hy) op w)

theorem cross_fresh {tid : Core → Nat} {A : List Applied} {X Y : List Effect} {t : Nat}
    (hX : ∀ x ∈ X, x.op.1 ∈ tids tid A) (ht : t ∉ tids tid A)
    (hY : ∀ y ∈ Y, ∀ op w, y = .ins op w → op.1 = t) : ∀ x ∈ X, ∀ y ∈ Y, EffRel x y := by
  intro x hx y hy op w hyeq heq
  have h1 := hY y hy op w hyeq
  have h2 := hX x hx
  rw [heq, h1] at h2
  exact ht h2

/-- Appending one fresh application with its removals `P` and its insertions keeps `Good`. -/
theorem good_step {tid : Core → Nat} {A : List Applied} {E : List Effect} {a : Applied}
    {P : List Effect} (hg : Good tid A E) (hfresh : tid a.core ∉ tids tid A)
    (hP : ∀ e ∈ P, e.op.1 ∈ tids tid A ∧ ∀ op w, e ≠ .ins op w) :
    Good tid (A ++ [a]) (E ++ (P ++ (spendKeys tid a.core).map (fun k => Effect.ins k false))) := by
  have hkeys : ∀ k ∈ spendKeys tid a.core, k.1 = tid a.core := fun k hk => (keysFrom_mem hk).1
  have hK : ∀ y ∈ (spendKeys tid a.core).map (fun k => Effect.ins k false), ∀ op w,
      y = .ins op w → op.1 = tid a.core := by
    intro y hy op w hyeq
    obtain ⟨k, hk, rfl⟩ := List.mem_map.1 hy
    cases hyeq
    exact hkeys _ hk
  have hPK : ∀ y ∈ P ++ (spendKeys tid a.core).map (fun k => Effect.ins k false), ∀ op w,
      y = .ins op w → op.1 = tid a.core := by
    intro y hy op w hyeq
    rcases List.mem_append.1 hy with h1 | h1
    · exact absurd hyeq ((hP y h1).2 op w)
    · exact hK y h1 op w hyeq
  have hold : ∀ x ∈ tids tid A, x ∈ tids tid (A ++ [a]) := by
    intro x hx; rw [tids_append]; exact List.mem_append_left _ hx
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [tids_append]
    refine List.pairwise_append.2 ⟨hg.nodup, List.pairwise_singleton _ _, ?_⟩
    intro x hx y hy hxy
    rw [List.mem_singleton.1 hy] at hxy
    exact hfresh (hxy ▸ hx)
  · intro e he
    rcases List.mem_append.1 he with h1 | h1
    · exact hold _ (hg.old e h1)
    · rcases List.mem_append.1 h1 with h2 | h2
      · exact hold _ (hP e h2).1
      · obtain ⟨k, hk, rfl⟩ := List.mem_map.1 h2
        rw [tids_append]
        exact List.mem_append_right _ (List.mem_singleton.2 (hkeys k hk))
  · intro op w he
    rcases List.mem_append.1 he with h1 | h1
    · exact hg.insFalse op w h1
    · rcases List.mem_append.1 h1 with h2 | h2
      · exact absurd rfl ((hP _ h2).2 op w)
      · obtain ⟨k, _, hk⟩ := List.mem_map.1 h2
        cases hk; rfl
  · refine List.pairwise_append.2 ⟨hg.rel, ?_, ?_⟩
    · refine List.pairwise_append.2 ⟨pairwise_noIns P (fun e he => (hP e he).2), ?_, ?_⟩
      · refine List.pairwise_map.2 ((keysFrom_nodup _ _ _).imp ?_)
        intro x y hxy op w hyeq
        cases hyeq
        exact hxy
      · exact cross_fresh (fun x hx => (hP x hx).1) hfresh hK
    · exact cross_fresh hg.old hfresh hPK

/-- From a state with `SInv`, a transaction at an index above 0 that passes `spendOk` has a
fresh identifier when the applied list extended by it satisfies `Consistent`. -/
theorem spend_fresh {tid : Core → Nat} {A : List Applied} {s : State} {b : Nat} {a : Applied}
    {rest : List Applied} (hs : SInv tid A s b) (hok : spendOk s a.core = true)
    (hc : Consistent tid (A ++ a :: rest)) : tid a.core ∉ tids tid A := by
  intro hm
  obtain ⟨e, he, heq⟩ := List.mem_map.1 hm
  have hcore : e.core = a.core :=
    hc e (List.mem_append_left _ he) a (List.mem_append_right _ (List.mem_cons_self _ _)) heq
  obtain ⟨hn, hne, hall⟩ := (spendOk_iff s a.core).1 hok
  cases hi : a.core.inputs with
  | nil => exact hne hi
  | cons op ops =>
    have hin : op ∈ a.core.inputs := by rw [hi]; exact List.mem_cons_self _ _
    have := hs.spent e he (hcore ▸ hn) op (hcore ▸ hin)
    exact this.1 (hall op hin)

/-- From a state with `SInv` at bound `h`, a transaction with nonce 0 and locktime `h` has a
fresh identifier when the applied list extended by it satisfies `Consistent`. -/
theorem cb_fresh {tid : Core → Nat} {A : List Applied} {s : State} {h : Nat} {a : Applied}
    {rest : List Applied} (hs : SInv tid A s h) (hn : a.core.nonce = 0)
    (hl : a.core.locktime = h) (hc : Consistent tid (A ++ a :: rest)) :
    tid a.core ∉ tids tid A := by
  intro hm
  obtain ⟨e, he, heq⟩ := List.mem_map.1 hm
  have hcore : e.core = a.core :=
    hc e (List.mem_append_left _ he) a (List.mem_append_right _ (List.mem_cons_self _ _)) heq
  have := hs.cb e he (hcore ▸ hn)
  rw [hcore, hl] at this
  exact Nat.lt_irrefl _ this

theorem spend_sinv {tid : Core → Nat} {A : List Applied} {s : State} {b : Nat} {a : Applied}
    (hs : SInv tid A s b) (hok : spendOk s a.core = true) (hfresh : tid a.core ∉ tids tid A) :
    SInv tid (A ++ [a]) (removeAll s a.core.inputs ++ spendKeys tid a.core) b := by
  obtain ⟨hn, _, hall⟩ := (spendOk_iff s a.core).1 hok
  have hkeys : ∀ k ∈ spendKeys tid a.core, k.1 = tid a.core := fun k hk => (keysFrom_mem hk).1
  have hold : ∀ x ∈ tids tid A, x ∈ tids tid (A ++ [a]) := by
    intro x hx; rw [tids_append]; exact List.mem_append_left _ hx
  have hnotkey : ∀ op, op.1 ∈ tids tid A → op ∉ spendKeys tid a.core := by
    intro op ho hk; rw [hkeys op hk] at ho; exact hfresh ho
  refine ⟨?_, ?_, ?_⟩
  · intro op hop
    rcases List.mem_append.1 hop with h1 | h1
    · exact hold _ (hs.present op (mem_removeAll.1 h1).1)
    · rw [tids_append, hkeys op h1]; exact List.mem_append_right _ (List.mem_singleton.2 rfl)
  · intro e he hen op hop
    rcases List.mem_append.1 he with h1 | h1
    · have := hs.spent e h1 hen op hop
      refine ⟨?_, hold _ this.2⟩
      intro hm
      rcases List.mem_append.1 hm with h2 | h2
      · exact this.1 (mem_removeAll.1 h2).1
      · exact hnotkey op this.2 h2
    · obtain rfl := List.mem_singleton.1 h1
      have hp := hs.present op (hall op hop)
      refine ⟨?_, hold _ hp⟩
      intro hm
      rcases List.mem_append.1 hm with h2 | h2
      · exact (mem_removeAll.1 h2).2 hop
      · exact hnotkey op hp h2
  · intro e he hen
    rcases List.mem_append.1 he with h1 | h1
    · exact hs.cb e h1 hen
    · rw [List.mem_singleton.1 h1] at hen; exact absurd hen hn

theorem cb_sinv {tid : Core → Nat} {A : List Applied} {s : State} {h : Nat} {a : Applied}
    (hs : SInv tid A s h) (hn : a.core.nonce = 0) (hl : a.core.locktime = h)
    (hfresh : tid a.core ∉ tids tid A) :
    SInv tid (A ++ [a]) (s ++ spendKeys tid a.core) (h + 1) := by
  have hkeys : ∀ k ∈ spendKeys tid a.core, k.1 = tid a.core := fun k hk => (keysFrom_mem hk).1
  have hold : ∀ x ∈ tids tid A, x ∈ tids tid (A ++ [a]) := by
    intro x hx; rw [tids_append]; exact List.mem_append_left _ hx
  refine ⟨?_, ?_, ?_⟩
  · intro op hop
    rcases List.mem_append.1 hop with h1 | h1
    · exact hold _ (hs.present op h1)
    · rw [tids_append, hkeys op h1]; exact List.mem_append_right _ (List.mem_singleton.2 rfl)
  · intro e he hen op hop
    rcases List.mem_append.1 he with h1 | h1
    · have := hs.spent e h1 hen op hop
      refine ⟨?_, hold _ this.2⟩
      intro hm
      rcases List.mem_append.1 hm with h2 | h2
      · exact this.1 h2
      · have := this.2; rw [hkeys op h2] at this; exact hfresh this
    · obtain rfl := List.mem_singleton.1 h1
      exact absurd hn hen
  · intro e he hen
    rcases List.mem_append.1 he with h1 | h1
    · exact Nat.lt_succ_of_lt (hs.cb e h1 hen)
    · rw [List.mem_singleton.1 h1, hl]; exact Nat.lt_succ_self h

theorem consistent_left {tid : Core → Nat} {L R : List Applied} (hc : Consistent tid (L ++ R)) :
    Consistent tid L :=
  fun a ha b hb => hc a (List.mem_append_left _ ha) b (List.mem_append_left _ hb)

theorem runTxs_good (tid : Core → Nat) (h : Nat) : ∀ (txs : List Tx) (i : Nat) (s : State)
    (A : List Applied) (E : List Effect), Good tid A E → SInv tid A s (h + 1) →
    Consistent tid (A ++ (runTxs tid h i s txs).2.1) →
    Good tid (A ++ (runTxs tid h i s txs).2.1) (E ++ (runTxs tid h i s txs).2.2) ∧
    ∀ s', (runTxs tid h i s txs).1 = .valid s' →
      SInv tid (A ++ (runTxs tid h i s txs).2.1) s' (h + 1)
  | [], i, s, A, E, hg, hs, _ => by
    simp only [runTxs, List.append_nil]
    refine ⟨hg, ?_⟩
    intro s' hs'
    cases hs'
    exact hs
  | t :: rest, i, s, A, E, hg, hs, hc => by
    by_cases hok : spendOk s t.core = true
    · let a : Applied := ⟨h, i, t.core⟩
      have hc0 : Consistent tid (A ++ a :: (runTxs tid h (i + 1)
          (insertKeys (removeAll s t.core.inputs) (spendKeys tid t.core)).1 rest).2.1) := by
        simpa [runTxs, hok] using hc
      have hfr : tid a.core ∉ tids tid A := spend_fresh hs hok hc0
      have hins := insertKeys_fresh (removeAll s t.core.inputs) (spendKeys tid t.core) (by
          intro k hk hm
          have := hs.present k (mem_removeAll.1 hm).1
          rw [(keysFrom_mem hk).1] at this
          exact hfr this) (keysFrom_nodup _ _ _)
      have hg' := good_step (a := a) (P := t.core.inputs.map Effect.rem) hg hfr (by
        intro e he
        obtain ⟨op, hop, rfl⟩ := List.mem_map.1 he
        exact ⟨hs.present op (((spendOk_iff s t.core).1 hok).2.2 op hop), fun _ _ h1 => by cases h1⟩)
      have hs' := spend_sinv (a := a) hs hok hfr
      rw [hins] at hc0
      have ih := runTxs_good tid h rest (i + 1) _ (A ++ [a]) _ hg' hs' (by simpa using hc0)
      simp only [runTxs, hok, if_true, hins]
      simpa [List.append_assoc] using ih
    · rw [show runTxs tid h i s (t :: rest) = (.invalid, [], []) by simp [runTxs, hok]]
      simp only [List.append_nil]
      refine ⟨hg, ?_⟩
      intro s' hs'
      cases hs'

theorem runBlock_good (tid : Core → Nat) (h : Nat) (s : State) (b : Block) (A : List Applied)
    (E : List Effect) (hg : Good tid A E) (hs : SInv tid A s h)
    (hc : Consistent tid (A ++ (runBlock tid h s b).2.1)) :
    Good tid (A ++ (runBlock tid h s b).2.1) (E ++ (runBlock tid h s b).2.2) ∧
    ∀ s', (runBlock tid h s b).1 = .valid s' → SInv tid (A ++ (runBlock tid h s b).2.1) s' (h + 1) := by
  cases b with
  | nil =>
    simp only [runBlock, List.append_nil]
    exact ⟨hg, fun s' hs' => by cases hs'⟩
  | cons cb rest =>
    by_cases hp : (isCoinbaseTx cb && !rest.any isCoinbaseTx) = true
    · by_cases hl : cb.core.locktime = h
      · let a : Applied := ⟨h, 0, cb.core⟩
        have hn : a.core.nonce = 0 := by
          have : isCoinbaseTx cb = true := by
            cases hx : isCoinbaseTx cb <;> simp_all
          simp [isCoinbaseTx] at this
          exact this.1
        have hc0 : Consistent tid (A ++ a :: (runTxs tid h 1
            (insertKeys s (spendKeys tid cb.core)).1 rest).2.1) := by
          simpa [runBlock, hp, hl] using hc
        have hfr : tid a.core ∉ tids tid A := cb_fresh hs hn hl hc0
        have hins := insertKeys_fresh s (spendKeys tid cb.core) (by
            intro k hk hm
            have := hs.present k hm
            rw [(keysFrom_mem hk).1] at this
            exact hfr this) (keysFrom_nodup _ _ _)
        have hg' := good_step (a := a) (P := []) hg hfr (by simp)
        have hs' := cb_sinv (a := a) hs hn hl hfr
        rw [hins] at hc0
        have ih := runTxs_good tid h rest 1 _ (A ++ [a]) _ hg' hs' (by simpa using hc0)
        simp only [runBlock, hp, hl, if_true, hins]
        simpa [List.append_assoc] using ih
      · rw [show runBlock tid h s (cb :: rest) = (.invalid, [], []) by simp [runBlock, hp, hl]]
        simp only [List.append_nil]
        exact ⟨hg, fun s' hs' => by cases hs'⟩
    · rw [show runBlock tid h s (cb :: rest) = (.invalid, [], []) by simp [runBlock, hp]]
      simp only [List.append_nil]
      exact ⟨hg, fun s' hs' => by cases hs'⟩

theorem runFrom_good (tid : Core → Nat) : ∀ (chain : Chain) (h : Nat) (s : State)
    (A : List Applied) (E : List Effect), Good tid A E → SInv tid A s h →
    Consistent tid (A ++ (runFrom tid h s chain).2.1) →
    Good tid (A ++ (runFrom tid h s chain).2.1) (E ++ (runFrom tid h s chain).2.2)
  | [], h, s, A, E, hg, _, _ => by simpa [runFrom] using hg
  | b :: rest, h, s, A, E, hg, hs, hc => by
    simp only [runFrom] at hc ⊢
    cases hr : (runBlock tid h s b).1 with
    | valid s' =>
      simp only [hr] at hc ⊢
      have hc1 : Consistent tid (A ++ (runBlock tid h s b).2.1) := by
        rw [← List.append_assoc] at hc; exact consistent_left hc
      have hb := runBlock_good tid h s b A E hg hs hc1
      have ih := runFrom_good tid rest (h + 1) s' _ _ hb.1 (hb.2 s' hr)
        (by simpa [List.append_assoc] using hc)
      simpa [List.append_assoc] using ih
    | invalid =>
      simp only [hr] at hc ⊢
      exact (runBlock_good tid h s b A E hg hs hc).1
    | noResult =>
      simp only [hr] at hc ⊢
      exact (runBlock_good tid h s b A E hg hs hc).1

/-- Parts (a) and (b) from the premise alone. -/
theorem runBase_good (tid : Core → Nat) (chain : Chain) (hp : Premise tid chain) :
    Good tid (runBase tid chain).2.1 (runBase tid chain).2.2 := by
  have := runFrom_good tid chain 0 [] [] []
    ⟨List.Pairwise.nil, by simp, by simp, List.Pairwise.nil⟩
    ⟨by simp, by simp, by simp⟩ (by simpa using hp)
  simpa using this

theorem mem_insOps {E : List Effect} {k : Outpoint} (hk : k ∈ insOps E) : ∃ w, Effect.ins k w ∈ E := by
  obtain ⟨e, he, hf⟩ := (List.mem_filterMap _ _).1 hk
  cases e with
  | ins op w => cases hf; exact ⟨w, he⟩
  | rem _ => cases hf

theorem insOps_nodup : ∀ (E : List Effect), E.Pairwise EffRel → (insOps E).Pairwise (· ≠ ·)
  | [], _ => List.Pairwise.nil
  | e :: E, hp => by
    have hp' := List.pairwise_cons.1 hp
    have ih := insOps_nodup E hp'.2
    cases e with
    | ins op w =>
      simp only [insOps, List.filterMap] at ih ⊢
      refine List.Pairwise.cons ?_ ih
      intro k hk
      obtain ⟨w', hw⟩ := mem_insOps hk
      exact hp'.1 _ hw k w' rfl
    | rem op =>
      simpa [insOps, List.filterMap] using ih

theorem no_ins_after_rem {E : List Effect} (hp : E.Pairwise EffRel) :
    ∀ pre post op w, E = pre ++ Effect.ins op w :: post → Effect.rem op ∉ pre := by
  intro pre post op w heq hm
  rw [heq] at hp
  exact (List.pairwise_append.1 hp).2.2 _ hm _ (List.mem_cons_self _ _) op w rfl rfl

/-! ## Part two: lemmas -/

theorem failFirst_nil (h : Nat) (ins resolved : List Outpoint) : ¬ FailFirst h ins resolved [] := by
  rintro ⟨pre, e, post, heq, _, _⟩
  cases pre <;> simp at heq

theorem unavFirst_nil (h : Nat) (ins resolved : List Outpoint) : ¬ UnavFirst h ins resolved [] := by
  rintro ⟨pre, post, heq, _⟩
  cases pre <;> simp at heq

theorem failsE4_unavailable (h : Nat) (ins resolved : List Outpoint) :
    failsE4 h ins resolved .unavailable = false := rfl

/-- `FailFirst` on a cons. -/
theorem failFirst_cons (h : Nat) (ins resolved : List Outpoint) (e : Event) (es : List Event) :
    FailFirst h ins resolved (e :: es) ↔
      failsE4 h ins resolved e = true ∨ (e ≠ .unavailable ∧ FailFirst h ins resolved es) := by
  constructor
  · rintro ⟨pre, x, post, heq, hx, hu⟩
    cases pre with
    | nil =>
      simp only [List.nil_append, List.cons.injEq] at heq
      exact Or.inl (heq.1 ▸ hx)
    | cons p pre =>
      simp only [List.cons_append, List.cons.injEq] at heq
      refine Or.inr ⟨?_, pre, x, post, heq.2, hx, fun hm => hu (List.mem_cons_of_mem _ hm)⟩
      intro he
      exact hu (heq.1 ▸ he ▸ List.mem_cons_self _ _)
  · rintro (hf | ⟨hne, pre, x, post, heq, hx, hu⟩)
    · exact ⟨[], e, es, rfl, hf, by simp⟩
    · refine ⟨e :: pre, x, post, by simp [heq], hx, ?_⟩
      intro hm
      rcases List.mem_cons.1 hm with h1 | h1
      · exact hne h1.symm
      · exact hu h1

/-- `UnavFirst` on a cons. -/
theorem unavFirst_cons (h : Nat) (ins resolved : List Outpoint) (e : Event) (es : List Event) :
    UnavFirst h ins resolved (e :: es) ↔
      e = .unavailable ∨ (failsE4 h ins resolved e = false ∧ UnavFirst h ins resolved es) := by
  constructor
  · rintro ⟨pre, post, heq, hp⟩
    cases pre with
    | nil =>
      simp only [List.nil_append, List.cons.injEq] at heq
      exact Or.inl heq.1
    | cons p pre =>
      simp only [List.cons_append, List.cons.injEq] at heq
      refine Or.inr ⟨?_, pre, post, heq.2, fun x hx => hp x (List.mem_cons_of_mem _ hx)⟩
      rw [heq.1]
      exact hp p (List.mem_cons_self _ _)
  · rintro (hu | ⟨hf, pre, post, heq, hp⟩)
    · exact ⟨[], es, by simp [hu], by simp⟩
    · refine ⟨e :: pre, post, by simp [heq], ?_⟩
      intro x hx
      rcases List.mem_cons.1 hx with h1 | h1
      · exact h1 ▸ hf
      · exact hp x h1

theorem finding_failed_iff (h : Nat) (ins resolved : List Outpoint) :
    ∀ es, insertionFinding h ins resolved es = some .failedCheck ↔ FailFirst h ins resolved es
  | [] => by simp [insertionFinding, failFirst_nil]
  | e :: es => by
    rw [failFirst_cons]
    by_cases hu : e = .unavailable
    · subst hu; simp [insertionFinding, failsE4_unavailable]
    · by_cases hf : failsE4 h ins resolved e = true
      · simp [insertionFinding, hu, hf]
      · simp [insertionFinding, hu, hf, finding_failed_iff h ins resolved es]

theorem finding_unav_iff (h : Nat) (ins resolved : List Outpoint) :
    ∀ es, insertionFinding h ins resolved es = some .unavailableRead ↔ UnavFirst h ins resolved es
  | [] => by simp [insertionFinding, unavFirst_nil]
  | e :: es => by
    rw [unavFirst_cons]
    by_cases hu : e = .unavailable
    · subst hu; simp [insertionFinding]
    · by_cases hf : failsE4 h ins resolved e = true
      · simp [insertionFinding, hu, hf]
      · simp [insertionFinding, hu, hf, finding_unav_iff h ins resolved es]

theorem finding_none_iff (h : Nat) (ins resolved : List Outpoint) (es : List Event) :
    insertionFinding h ins resolved es = none ↔
      ¬ FailFirst h ins resolved es ∧ ¬ UnavFirst h ins resolved es := by
  rw [← finding_failed_iff, ← finding_unav_iff]
  cases insertionFinding h ins resolved es with
  | none => simp
  | some f => cases f <;> simp

theorem finding_filter_consume (h : Nat) (ins resolved : List Outpoint) :
    ∀ es, insertionFinding h ins resolved (es.filter (fun e => !isConsume e)) =
      insertionFinding h ins resolved es
  | [] => rfl
  | e :: es => by
    have ih := finding_filter_consume h ins resolved es
    simp only [isConsume] at ih
    have hc : ∀ w, failsE4 h ins resolved (.consume w) = false := fun _ => rfl
    cases e <;> simp [List.filter, isConsume, insertionFinding, ih, hc]

theorem failsE4_forget (h : Nat) (ins resolved : List Outpoint) (e : Event) :
    failsE4 h ins resolved (forget e) = failsE4 h ins resolved e := by
  cases e with
  | parentEntry w op _ _ => cases w <;> rfl
  | parentLeaf w op _ => cases w <;> rfl
  | _ => rfl

theorem forget_unavailable (e : Event) : forget e = .unavailable ↔ e = .unavailable := by
  cases e <;> simp [forget]

theorem finding_map_forget (h : Nat) (ins resolved : List Outpoint) :
    ∀ es, insertionFinding h ins resolved (es.map forget) = insertionFinding h ins resolved es
  | [] => rfl
  | e :: es => by
    simp only [List.map, insertionFinding, forget_unavailable, failsE4_forget,
      finding_map_forget h ins resolved es]

theorem baseline_cons (e : Event) (es : List Event) :
    baselineFinding (e :: es) =
      if e = .unavailable then some .unavailableRead else baselineFinding es := by
  by_cases hu : e = .unavailable
  · subst hu; simp [baselineFinding]
  · have : ¬ Event.unavailable = e := fun h1 => hu h1.symm
    simp [baselineFinding, hu, this]

theorem finding_eq_baseline (h : Nat) (ins resolved : List Outpoint) :
    ∀ es, (∀ e ∈ es, failsE4 h ins resolved e = false) →
      insertionFinding h ins resolved es = baselineFinding es
  | [] => fun _ => rfl
  | e :: es => fun hall => by
    rw [baseline_cons]
    have hf := hall e (List.mem_cons_self _ _)
    have ih := finding_eq_baseline h ins resolved es (fun x hx => hall x (List.mem_cons_of_mem _ hx))
    by_cases hu : e = .unavailable
    · simp [insertionFinding, hu]
    · simp [insertionFinding, hu, hf, ih]

theorem finding_ne_baseline_iff (h : Nat) (ins resolved : List Outpoint) :
    ∀ es, insertionFinding h ins resolved es ≠ baselineFinding es ↔ FailFirst h ins resolved es
  | [] => by simp [insertionFinding, baselineFinding, failFirst_nil]
  | e :: es => by
    rw [baseline_cons, failFirst_cons]
    by_cases hu : e = .unavailable
    · subst hu; simp [insertionFinding, failsE4_unavailable]
    · by_cases hf : failsE4 h ins resolved e = true
      · have hb : baselineFinding es ≠ some .failedCheck := by
          unfold baselineFinding; split <;> simp
        simp [insertionFinding, hu, hf, Ne.symm hb]
      · simp [insertionFinding, hu, hf, finding_ne_baseline_iff h ins resolved es]

theorem store_noOutcome_iff (r : BlockResult) (h : Nat) (ins resolved : List Outpoint)
    (es : List Event) : storeOutcome r h ins resolved es = .noOutcome ↔ r = .noResult := by
  cases r <;> cases hf : insertionFinding h ins resolved es <;> simp [storeOutcome, hf]

theorem store_finding_iff (r : BlockResult) (h : Nat) (ins resolved : List Outpoint)
    (es : List Event) (hr : r ≠ .noResult) (f : Finding) :
    storeOutcome r h ins resolved es = .finding f ↔ insertionFinding h ins resolved es = some f := by
  cases r with
  | noResult => exact absurd rfl hr
  | _ => cases hf : insertionFinding h ins resolved es <;> simp [storeOutcome, hf]

theorem store_noFinding_iff (r : BlockResult) (h : Nat) (ins resolved : List Outpoint)
    (es : List Event) (hr : r ≠ .noResult) :
    storeOutcome r h ins resolved es = .noFinding ↔ insertionFinding h ins resolved es = none := by
  cases r with
  | noResult => exact absurd rfl hr
  | _ => cases hf : insertionFinding h ins resolved es <;> simp [storeOutcome, hf]

/-! ## Part one: lemmas for part (c) -/

theorem any_false {tid : Core → Nat} {seen : List Applied} {a : Applied}
    (h : (seen.any fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core)) = false) :
    ∀ e ∈ seen, tid e.core = tid a.core → e.core = a.core := by
  intro e he ht
  by_contra hne
  have : (seen.any fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core)) = true :=
    List.any_eq_true.2 ⟨e, he, by simp [ht, hne]⟩
  rw [h] at this
  exact Bool.false_ne_true this

theorem breakAt_none_of_consistent (tid : Core → Nat) :
    ∀ (L seen : List Applied), Consistent tid (seen ++ L) → breakAt tid seen L = none
  | [], _, _ => rfl
  | a :: L, seen, hc => by
    have hany : (seen.any fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core))
        = false := by
      cases hx : (seen.any fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core))
      · rfl
      · obtain ⟨e, he, hp⟩ := List.any_eq_true.1 hx
        simp at hp
        exact absurd (hc e (List.mem_append_left _ he) a
          (List.mem_append_right _ (List.mem_cons_self _ _)) hp.1) hp.2
    simp only [breakAt, hany]
    exact breakAt_none_of_consistent tid L (seen ++ [a]) (by simpa using hc)

theorem consistent_snoc {tid : Core → Nat} {seen : List Applied} {a : Applied}
    (hc : Consistent tid seen) (hs : ∀ e ∈ seen, tid e.core = tid a.core → e.core = a.core) :
    Consistent tid (seen ++ [a]) := by
  intro x hx y hy hxy
  rcases List.mem_append.1 hx with hx | hx <;> rcases List.mem_append.1 hy with hy | hy
  · exact hc x hx y hy hxy
  · rw [List.mem_singleton.1 hy] at hxy ⊢; exact hs x hx hxy
  · rw [List.mem_singleton.1 hx] at hxy ⊢; exact (hs y hy hxy.symm).symm
  · rw [List.mem_singleton.1 hx, List.mem_singleton.1 hy]

theorem consistent_of_breakAt_none (tid : Core → Nat) :
    ∀ (L seen : List Applied), Consistent tid seen → breakAt tid seen L = none →
      Consistent tid (seen ++ L)
  | [], seen, hc, _ => by simpa using hc
  | a :: L, seen, hc, hb => by
    cases hx : (seen.any fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core))
    · simp only [breakAt, hx] at hb
      have := consistent_of_breakAt_none tid L (seen ++ [a]) (consistent_snoc hc (any_false hx)) hb
      simpa using this
    · simp [breakAt, hx] at hb

theorem breakAt_some (tid : Core → Nat) :
    ∀ (L seen : List Applied) (k : Nat), breakAt tid seen L = some k →
      ∃ pre a post, L = pre ++ a :: post ∧ a.height = k ∧
        (∃ e ∈ seen ++ pre, tid e.core = tid a.core ∧ e.core ≠ a.core) ∧
        breakAt tid seen pre = none
  | [], _, _, hb => by simp [breakAt] at hb
  | a :: L, seen, k, hb => by
    cases hx : (seen.any fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core))
    · simp only [breakAt, hx] at hb
      obtain ⟨pre, x, post, heq, hh, ⟨e, he, ht⟩, hn⟩ := breakAt_some tid L (seen ++ [a]) k hb
      refine ⟨a :: pre, x, post, by simp [heq], hh, ⟨e, by simpa using he, ht⟩, ?_⟩
      simp only [breakAt, hx]
      exact hn
    · simp only [breakAt, hx, if_true] at hb
      obtain ⟨e, he, hp⟩ := List.any_eq_true.1 hx
      simp at hp
      exact ⟨[], a, L, rfl, Option.some.inj hb, ⟨e, by simpa using he, hp⟩, rfl⟩

theorem breakAt_append_none (tid : Core → Nat) :
    ∀ (L seen R : List Applied), breakAt tid seen L = none →
      breakAt tid seen (L ++ R) = breakAt tid (seen ++ L) R
  | [], seen, R, _ => by simp
  | a :: L, seen, R, hb => by
    cases hx : (seen.any fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core))
    · have hb' : breakAt tid (seen ++ [a]) L = none := by simpa [breakAt, hx] using hb
      have := breakAt_append_none tid L (seen ++ [a]) R hb'
      show breakAt tid seen (a :: (L ++ R)) = _
      simp [breakAt, hx, this]
    · simp [breakAt, hx] at hb

theorem breakAt_append_some (tid : Core → Nat) :
    ∀ (L seen R : List Applied) (k : Nat), breakAt tid seen L = some k →
      breakAt tid seen (L ++ R) = some k
  | [], _, _, _, hb => by simp [breakAt] at hb
  | a :: L, seen, R, k, hb => by
    cases hx : (seen.any fun e => decide (tid e.core = tid a.core) && !decide (e.core = a.core))
    · simp only [breakAt, hx] at hb
      simp only [List.cons_append, breakAt, hx]
      exact breakAt_append_some tid L (seen ++ [a]) R k hb
    · simp only [breakAt, hx, if_true] at hb
      simp only [List.cons_append, breakAt, hx, if_true]
      exact hb

theorem premise_iff (tid : Core → Nat) (chain : Chain) :
    Premise tid chain ↔ firstBreak tid chain = none := by
  constructor
  · intro hp
    exact breakAt_none_of_consistent tid _ [] (by simpa using hp)
  · intro hb
    have := consistent_of_breakAt_none tid _ [] (fun _ h1 => absurd h1 (List.not_mem_nil _)) hb
    simpa using this

theorem runTxs_height (tid : Core → Nat) (h : Nat) :
    ∀ (txs : List Tx) (i : Nat) (s : State), ∀ a ∈ (runTxs tid h i s txs).2.1, a.height = h
  | [], _, _ => by simp [runTxs]
  | t :: rest, i, s => by
    by_cases hok : spendOk s t.core = true
    · intro a ha
      simp only [runTxs, hok, if_true, List.mem_cons] at ha
      rcases ha with rfl | ha
      · rfl
      · exact runTxs_height tid h rest _ _ a ha
    · intro a ha
      rw [show runTxs tid h i s (t :: rest) = (.invalid, [], []) by simp [runTxs, hok]] at ha
      cases ha

theorem runBlock_height (tid : Core → Nat) (h : Nat) (s : State) (b : Block) :
    ∀ a ∈ (runBlock tid h s b).2.1, a.height = h := by
  intro a ha
  cases b with
  | nil => cases ha
  | cons cb rest =>
    by_cases hp : (isCoinbaseTx cb && !rest.any isCoinbaseTx) = true
    · by_cases hl : cb.core.locktime = h
      · simp only [runBlock, hp, hl, if_true, List.mem_cons] at ha
        rcases ha with rfl | ha
        · rfl
        · exact runTxs_height tid h rest _ _ a ha
      · rw [show runBlock tid h s (cb :: rest) = (.invalid, [], []) by simp [runBlock, hp, hl]] at ha
        cases ha
    · rw [show runBlock tid h s (cb :: rest) = (.invalid, [], []) by simp [runBlock, hp]] at ha
      cases ha

/-- An applied entry lies in a block of the chain that has a result, after valid blocks. -/
theorem runFrom_height (tid : Core → Nat) : ∀ (chain : Chain) (h : Nat) (s : State),
    ∀ a ∈ (runFrom tid h s chain).2.1, h ≤ a.height ∧ a.height - h < chain.length ∧
      ((runFrom tid h s chain).1.take (a.height - h)).length = a.height - h ∧
      ∀ r ∈ (runFrom tid h s chain).1.take (a.height - h), ∃ s', r = .valid s'
  | [], _, _ => by simp [runFrom]
  | b :: rest, h, s => by
    intro a ha
    simp only [runFrom] at ha ⊢
    cases hr : (runBlock tid h s b).1 with
    | valid s' =>
      simp only [hr] at ha ⊢
      rcases List.mem_append.1 ha with h1 | h1
      · have := runBlock_height tid h s b a h1
        subst this
        simp
      · obtain ⟨h2, h3, h4, h5⟩ := runFrom_height tid rest (h + 1) s' a h1
        have heq : a.height - h = (a.height - (h + 1)) + 1 := by omega
        rw [heq]
        refine ⟨by omega, by simp; omega, by rw [List.take, List.length_cons, h4], ?_⟩
        intro r hr'
        simp only [List.take, List.mem_cons] at hr'
        rcases hr' with rfl | hr'
        · exact ⟨s', rfl⟩
        · exact h5 r hr'
    | invalid =>
      simp only [hr] at ha ⊢
      have := runBlock_height tid h s b a ha
      subst this
      simp
    | noResult =>
      simp only [hr] at ha ⊢
      have := runBlock_height tid h s b a ha
      subst this
      simp

/-- The run of the first `j` blocks: results are the first `j` results; the applied list is
a prefix, and every later entry has height at least `h + j`. -/
theorem runFrom_take (tid : Core → Nat) : ∀ (chain : Chain) (h : Nat) (s : State) (j : Nat),
    (runFrom tid h s (chain.take j)).1 = (runFrom tid h s chain).1.take j ∧
    ∃ rest, (runFrom tid h s chain).2.1 = (runFrom tid h s (chain.take j)).2.1 ++ rest ∧
      ∀ a ∈ rest, h + j ≤ a.height
  | [], _, _, _ => by simp [runFrom]
  | b :: chain, h, s, 0 => by
    refine ⟨by simp [runFrom], (runFrom tid h s (b :: chain)).2.1, by simp [runFrom], ?_⟩
    intro a ha
    simpa using (runFrom_height tid (b :: chain) h s a ha).1
  | b :: chain, h, s, j + 1 => by
    simp only [List.take, runFrom]
    cases hr : (runBlock tid h s b).1 with
    | valid s' =>
      simp only [hr]
      obtain ⟨ih1, rest, ih2, ih3⟩ := runFrom_take tid chain (h + 1) s' j
      refine ⟨by simp [ih1], rest, by simp [ih2], ?_⟩
      intro a ha
      have := ih3 a ha
      omega
    | invalid =>
      simp only [hr]
      exact ⟨by simp, [], by simp, by simp⟩
    | noResult =>
      simp only [hr]
      exact ⟨by simp, [], by simp, by simp⟩

theorem take_take_of_le {α : Type} : ∀ (l : List α) (j k : Nat), j ≤ k → (l.take k).take j = l.take j
  | [], _, _, _ => by simp
  | _ :: _, 0, _, _ => by simp
  | _ :: _, _ + 1, 0, hjk => absurd hjk (Nat.not_succ_le_zero _)
  | x :: l, j + 1, k + 1, hjk => by
    simp [take_take_of_le l j k (Nat.le_of_succ_le_succ hjk)]

theorem replicate_prefix {α : Type} (x : α) : ∀ (m n : Nat), m ≤ n →
    List.replicate m x <+: List.replicate n x
  | 0, _, _ => List.nil_prefix _
  | _ + 1, 0, hmn => absurd hmn (Nat.not_succ_le_zero _)
  | m + 1, n + 1, hmn => by
    obtain ⟨t, ht⟩ := replicate_prefix x m n (Nat.le_of_succ_le_succ hmn)
    exact ⟨t, by simp [List.replicate, ht]⟩

theorem prefix_append_left {α : Type} (l : List α) {a b : List α} (h : a <+: b) :
    l ++ a <+: l ++ b := by
  obtain ⟨t, ht⟩ := h
  exact ⟨t, by rw [List.append_assoc, ht]⟩

/-- The break half of part (c). -/
theorem applyChain_break (tid : Core → Nat) (chain : Chain) (hp : ¬ Premise tid chain) :
    ∃ k, firstBreak tid chain = some k ∧ k < chain.length ∧
      (∃ pre a post, (runBase tid chain).2.1 = pre ++ a :: post ∧ a.height = k ∧
        Consistent tid pre ∧ ∃ e ∈ pre, tid e.core = tid a.core ∧ e.core ≠ a.core) ∧
      ((runBase tid chain).1.take k).length = k ∧
      (∀ r ∈ (runBase tid chain).1.take k, ∃ s, r = .valid s) ∧
      applyChain tid chain =
        (runBase tid chain).1.take k ++ List.replicate (chain.length - k) .noResult := by
  cases hfb : firstBreak tid chain with
  | none => exact absurd ((premise_iff tid chain).2 hfb) hp
  | some k =>
    obtain ⟨pre, a, post, heq, hh, ⟨e, he, ht⟩, hn⟩ := breakAt_some tid _ [] k hfb
    have hcp := consistent_of_breakAt_none tid pre [] (fun _ h1 => absurd h1 (List.not_mem_nil _)) hn
    have hmem : a ∈ (runBase tid chain).2.1 := by rw [heq]; simp
    obtain ⟨_, h2, h3, h4⟩ := runFrom_height tid chain 0 [] a hmem
    simp only [Nat.sub_zero, hh] at h2 h3 h4
    refine ⟨k, rfl, h2, ⟨pre, a, post, heq, hh, by simpa using hcp, e, by simpa using he, ht⟩,
      h3, h4, ?_⟩
    simp only [applyChain, hfb]

/-- The prefix half of part (c). -/
theorem applyChain_prefix (tid : Core → Nat) (chain : Chain) (j : Nat) :
    applyChain tid (chain.take j) <+: applyChain tid chain := by
  obtain ⟨hres, rest, happ, hrest⟩ := runFrom_take tid chain 0 [] j
  have hres' : (runBase tid (chain.take j)).1 = (runBase tid chain).1.take j := hres
  have happ' : (runBase tid chain).2.1 = (runBase tid (chain.take j)).2.1 ++ rest := happ
  have hlen : (chain.take j).length ≤ j ∧ (chain.take j).length ≤ chain.length := by
    rw [List.length_take]; exact ⟨Nat.min_le_left _ _, Nat.min_le_right _ _⟩
  unfold applyChain
  cases h1 : firstBreak tid (chain.take j) with
  | some k =>
    have h2 : firstBreak tid chain = some k := by
      unfold firstBreak; rw [happ']; exact breakAt_append_some tid _ [] rest k h1
    rw [h2]
    obtain ⟨pre, a, post, heq, hh, _, _⟩ := breakAt_some tid _ [] k h1
    have hmem : a ∈ (runBase tid (chain.take j)).2.1 := by rw [heq]; simp
    have hk := (runFrom_height tid (chain.take j) 0 [] a hmem).2.1
    simp only [Nat.sub_zero, hh] at hk
    simp only [hres']
    rw [take_take_of_le _ k j (by omega)]
    exact prefix_append_left _ (replicate_prefix _ _ _ (by omega))
  | none =>
    cases h2 : firstBreak tid chain with
    | none => simp only [hres']; exact List.take_prefix _ _
    | some k =>
      have h3 : breakAt tid (runBase tid (chain.take j)).2.1 rest = some k := by
        have := h2; unfold firstBreak at this h1
        rw [happ', breakAt_append_none tid _ [] rest h1] at this
        simpa using this
      obtain ⟨pre, a, post, heq, hh, _, _⟩ := breakAt_some tid _ _ k h3
      have hjk : j ≤ k := by
        have := hrest a (by rw [heq]; simp); omega
      simp only [hres']
      rw [← take_take_of_le (runBase tid chain).1 j k hjk]
      exact (List.take_prefix _ _).trans (List.prefix_append _ _)

/-! ## Registered theorem -/

/-- The bounded model's contract: (a) and (b) under `Premise`, with no hypothesis on the block
results; (c) the premise break, (d) to (f) the event-order classifier, (g) the composition.
A chain whose every `applyChain` result is `valid` satisfies `Premise`, since by (c) a premise
break gives `noResult` to a block of the chain, so (a) and (b) cover it. A chain whose every
`runBase` result is `valid` need not satisfy `Premise` (the T9 example). -/
theorem outpoint_insertion_contract (tid : Core → Nat) (chain : Chain) (r : BlockResult)
    (h : Nat) (ins resolved : List Outpoint) (es : List Event) :
    -- (a)
    (Premise tid chain →
      ((runBase tid chain).2.1.map (fun a => tid a.core)).Nodup) ∧
    -- (b)
    (Premise tid chain →
      (∀ op w, Effect.ins op w ∈ (runBase tid chain).2.2 → w = false) ∧
      (insOps (runBase tid chain).2.2).Nodup ∧
      (∀ pre post op w, (runBase tid chain).2.2 = pre ++ Effect.ins op w :: post →
        Effect.rem op ∉ pre)) ∧
    -- (c)
    (Premise tid chain → applyChain tid chain = (runBase tid chain).1) ∧
    (¬ Premise tid chain → ∃ k, firstBreak tid chain = some k ∧ k < chain.length ∧
      (∃ pre a post, (runBase tid chain).2.1 = pre ++ a :: post ∧ a.height = k ∧
        Consistent tid pre ∧ ∃ e ∈ pre, tid e.core = tid a.core ∧ e.core ≠ a.core) ∧
      ((runBase tid chain).1.take k).length = k ∧
      (∀ r ∈ (runBase tid chain).1.take k, ∃ s, r = .valid s) ∧
      applyChain tid chain =
        (runBase tid chain).1.take k ++ List.replicate (chain.length - k) .noResult) ∧
    (∀ j, applyChain tid (chain.take j) <+: applyChain tid chain) ∧
    -- (d)
    (insertionFinding h ins resolved es = some .failedCheck ↔ FailFirst h ins resolved es) ∧
    (insertionFinding h ins resolved es = some .unavailableRead ↔ UnavFirst h ins resolved es) ∧
    (insertionFinding h ins resolved es = none ↔
      ¬ FailFirst h ins resolved es ∧ ¬ UnavFirst h ins resolved es) ∧
    insertionFinding h ins resolved (es.filter (fun e => !isConsume e)) =
      insertionFinding h ins resolved es ∧
    -- (e)
    (∀ es', es'.map forget = es.map forget →
      insertionFinding h ins resolved es' = insertionFinding h ins resolved es) ∧
    -- (f)
    ((∀ e ∈ es, failsE4 h ins resolved e = false) →
      insertionFinding h ins resolved es = baselineFinding es) ∧
    (insertionFinding h ins resolved es ≠ baselineFinding es ↔ FailFirst h ins resolved es) ∧
    -- (g)
    (storeOutcome r h ins resolved es = .noOutcome ↔ r = .noResult) ∧
    (r ≠ .noResult → ∀ f, (storeOutcome r h ins resolved es = .finding f ↔
      insertionFinding h ins resolved es = some f)) ∧
    (r ≠ .noResult → (storeOutcome r h ins resolved es = .noFinding ↔
      insertionFinding h ins resolved es = none)) := by
  refine ⟨fun hp => (runBase_good tid chain hp).nodup,
    fun hp => ⟨(runBase_good tid chain hp).insFalse, insOps_nodup _ (runBase_good tid chain hp).rel,
      no_ins_after_rem (runBase_good tid chain hp).rel⟩,
    fun hp => by simp only [applyChain, (premise_iff tid chain).1 hp],
    applyChain_break tid chain, applyChain_prefix tid chain,
    finding_failed_iff h ins resolved es, finding_unav_iff h ins resolved es,
    finding_none_iff h ins resolved es, finding_filter_consume h ins resolved es, ?_,
    finding_eq_baseline h ins resolved es, finding_ne_baseline_iff h ins resolved es,
    store_noOutcome_iff r h ins resolved es, store_finding_iff r h ins resolved es,
    store_noFinding_iff r h ins resolved es⟩
  intro es' hmap
  rw [← finding_map_forget h ins resolved es', hmap, finding_map_forget]

/-! ## Case examples (unregistered) -/

namespace Examples

def c0 : Core := ⟨0, [], 0, [true]⟩
def c1 : Core := ⟨0, [], 1, [true]⟩
def c2 : Core := ⟨0, [], 2, [true]⟩
def s0 : Core := ⟨1, [(1, 0)], 0, [true]⟩
def sR : Core := ⟨1, [(2, 0)], 0, [true]⟩
def s1 : Core := ⟨1, [(1, 0)], 0, [true, true]⟩
def s2 : Core := ⟨1, [(6, 1)], 0, [true]⟩
def n0 : Core := ⟨1, [], 0, [true]⟩
def z : Core := ⟨0, [(1, 0)], 0, [true]⟩
def c7 : Core := ⟨0, [], 0, [false, true]⟩
def cF : Core := ⟨0, [], 0, [false]⟩
def cS10 : Core := ⟨0, [], 1, [true, false]⟩
def dupIn : Core := ⟨1, [(1, 0), (1, 0)], 0, [true]⟩

/-- Injective on the cores of the examples. -/
def tidA (c : Core) : Nat :=
  if c = c0 then 1 else if c = c1 then 2 else if c = c2 then 3 else if c = s0 then 4
  else if c = sR then 5 else if c = s1 then 6 else if c = s2 then 7 else if c = n0 then 8
  else if c = z then 9 else if c = c7 then 10 else if c = cF then 11 else if c = cS10 then 12
  else if c = dupIn then 13 else 0

/-- Maps the different cores `s0` and `c1` to one identifier. -/
def tidB (c : Core) : Nat := if c = s0 then 2 else tidA c

def cbTx (c : Core) : Tx := ⟨c, true⟩

def spTx (c : Core) : Tx := ⟨c, false⟩

/-- T1: coinbases at heights 0 and 1; every insertion has `wasPresent` false. -/
example : applyChain tidA [[cbTx c0], [cbTx c1]] = [.valid [(1, 0)], .valid [(1, 0), (2, 0)]] := by
  decide

/-- T1: the effects. -/
example : (runBase tidA [[cbTx c0], [cbTx c1]]).2.2 = [.ins (1, 0) false, .ins (2, 0) false] := by
  decide

/-- T2: a spend of an earlier block's coinbase output and a same-block spend of output 1 of
the transaction at index 1; the spender at index 2 inserts output index 0. -/
example : applyChain tidA [[cbTx c0], [cbTx c1, spTx s1, spTx s2]] =
    [.valid [(1, 0)], .valid [(2, 0), (6, 0), (7, 0)]] := by decide

/-- T2: the effects, every insertion flag false. -/
example : (runBase tidA [[cbTx c0], [cbTx c1, spTx s1, spTx s2]]).2.2 =
    [.ins (1, 0) false, .ins (2, 0) false, .rem (1, 0), .ins (6, 0) false, .ins (6, 1) false,
     .rem (6, 1), .ins (7, 0) false] := by decide

/-- T3: the two coinbases of T1 have different cores. -/
example : c0 ≠ c1 := by decide

/-- T3: a height-1 coinbase whose core equals the height-0 coinbase core is `invalid`. -/
example : applyChain tidA [[cbTx c0], [cbTx c0]] = [.valid [(1, 0)], .invalid] := by decide

/-- T4: a non-coinbase core applied again in a later block is `invalid`. -/
example : applyChain tidA [[cbTx c0], [cbTx c1, spTx s0], [cbTx c2, spTx s0]] =
    [.valid [(1, 0)], .valid [(2, 0), (4, 0)], .invalid] := by decide

/-- T4: applied again in the same block, `invalid`. -/
example : applyChain tidA [[cbTx c0], [cbTx c1, spTx s0, spTx s0]] =
    [.valid [(1, 0)], .invalid] := by decide

/-- T4: a non-coinbase transaction with no input is `invalid`. -/
example : applyChain tidA [[cbTx c0, spTx n0]] = [.invalid] := by decide

/-- T5: index 1 with nonce 0 and `cbRest` true: `invalid`, no transaction applied, although
the coinbase would break the premise. -/
example : applyChain tidB [[cbTx c0, spTx s0], [cbTx c1, cbTx z]] =
    [.valid [(2, 0)], .invalid] := by decide

/-- T5: the same with `cbRest` false: the coinbase breaks the premise, `noResult`. -/
example : applyChain tidB [[cbTx c0, spTx s0], [cbTx c1, spTx z]] =
    [.valid [(2, 0)], .noResult] := by decide

/-- T5: the same with `cbRest` false and no premise break: `invalid` (nonce 0, input present). -/
example : applyChain tidA [[cbTx c0], [cbTx c1, spTx z]] = [.valid [(1, 0)], .invalid] := by
  decide

/-- T5: a first transaction with nonce 1 makes the block `invalid`. -/
example : applyChain tidA [[cbTx c0], [cbTx s0]] = [.valid [(1, 0)], .invalid] := by decide

/-- T6: an earlier block inserted and removed `(1, 0)`; the attempt to insert it again is
`invalid`. -/
example : applyChain tidA [[cbTx c0, spTx s0], [cbTx c0]] = [.valid [(4, 0)], .invalid] := by
  decide

/-- T6: an earlier block inserted and removed `(2, 0)`; the attempt under the
premise-breaking `tidB` is `noResult`. -/
example : applyChain tidB [[cbTx c0, spTx s0, spTx sR], [cbTx c1]] =
    [.valid [(5, 0)], .noResult] := by decide

/-- T6: earlier transactions of the same block inserted and removed `(2, 0)`; the attempt
under the injective `tidA` is `invalid`. -/
example : applyChain tidA [[cbTx c0], [cbTx c1, spTx sR, spTx c1]] =
    [.valid [(1, 0)], .invalid] := by decide

/-- T6: in the same block `s1` inserts `(6, 1)` and `s2` removes it; `s1` applied again, which
would insert `(6, 1)` again, is `invalid` under the injective `tidA`: its first application
removed its input `(1, 0)` (`R1`). -/
example : applyChain tidA [[cbTx c0], [cbTx c1, spTx s1, spTx s2, spTx s1]] =
    [.valid [(1, 0)], .invalid] := by decide

/-- T7: output 0 non-spendable, output 1 spendable: the key has output index 1. -/
example : runBase tidA [[cbTx c7]] = ([.valid [(10, 1)]], [⟨0, 0, c7⟩], [.ins (10, 1) false]) := by
  decide

/-- T7: a coinbase with only a non-spendable output has no effect and no key. -/
example : runBase tidA [[cbTx cF]] = ([.valid []], [⟨0, 0, cF⟩], []) := by decide

/-- The T8 chain: block 1 of three breaks the premise under `tidB`. -/
def t8 : Chain := [[cbTx c0, spTx s0], [cbTx c1], [cbTx c2]]

/-- T8: `valid`, `noResult`, `noResult`. -/
example : applyChain tidB t8 = [.valid [(2, 0)], .noResult, .noResult] := by decide

/-- T8: a break inside one block gives `noResult` for that block. -/
example : applyChain tidB [[cbTx c0], [cbTx c1, spTx s0]] = [.valid [(1, 0)], .noResult] := by
  decide

/-- T9: the T8 chain under the baseline gives three `valid` results. -/
example : (runBase tidB t8).1 = [.valid [(2, 0)], .valid [(2, 0)], .valid [(2, 0), (3, 0)]] := by
  decide

/-- S1: keyed parent entry of the derivation at an inserted outpoint. -/
example : insertionFinding 1 [(2, 0)] []
    [.parentEntry .derivation (2, 0) .keyed false, .consume .derivation] = some .failedCheck := by
  decide

/-- S2: a multi-outpoint read. -/
example : insertionFinding 1 [(2, 0)] [] [.parentEntry .derivation (2, 0) .multi false] =
    some .failedCheck := by decide

/-- S3: a leaf, whatever entry it holds (first value). -/
example : insertionFinding 1 [(2, 0)] [] [.parentLeaf .derivation (2, 0) 7] =
    some .failedCheck := by decide

/-- S3: a leaf, whatever entry it holds (second value). -/
example : insertionFinding 1 [(2, 0)] [] [.parentLeaf .derivation (2, 0) 8] =
    some .failedCheck := by decide

/-- S4: an entry at an output created earlier in the same block, which is not in `resolved`. -/
example : insertionFinding 1 [(2, 0), (4, 0)] [(1, 0)]
    [.parentEntry .derivation (4, 0) .keyed false] = some .failedCheck := by decide

/-- S4: a leaf at an output created earlier in the same block. -/
example : insertionFinding 1 [(2, 0), (4, 0)] [(1, 0)] [.parentLeaf .derivation (4, 0) 3] =
    some .failedCheck := by decide

/-- S5: an outpoint resolved as a present entry of `U_parent`. -/
example : insertionFinding 1 [(2, 0)] [(2, 0)] [.parentEntry .derivation (2, 0) .keyed true] =
    none := by decide

/-- S6: a definitive absence. -/
example : insertionFinding 1 [(2, 0)] [] [.parentAbsent .derivation (2, 0)] = none := by decide

/-- S7: no event. -/
example : insertionFinding 1 [(2, 0)] [] [] = none := by decide

/-- S7: events only for other outpoints. -/
example : insertionFinding 1 [(2, 0)] [] [.parentEntry .derivation (3, 0) .keyed true,
    .parentLeaf .derivation (2, 1) 0] = none := by decide

/-- S8: the private-candidate view. -/
example : insertionFinding 1 [(2, 0)] [] [.candidateEntry .derivation (2, 0)] = none := by decide

/-- S9: obtained by the operation that includes input resolution. -/
example : insertionFinding 1 [(2, 0)] [] [.parentEntry .resolution (2, 0) .keyed true] = none := by
  decide

/-- S10: `ins` from a core with spendable output 0 and non-spendable output 1. -/
example : spendKeys tidA cS10 = [(12, 0)] := by decide

/-- S10: an entry at output 1. -/
example : insertionFinding 1 (spendKeys tidA cS10) [] [.parentEntry .derivation (12, 1) .keyed true] =
    none := by decide

/-- S11: a definitive absence at height 0. -/
example : insertionFinding 0 [(2, 0)] [] [.parentAbsent .derivation (2, 0)] = none := by decide

/-- S11, the height clause of E4: an entry event at height 0, a state that the specification
excludes (every parent-branch lookup at height 0 is a definitive absence). -/
example : insertionFinding 0 [(2, 0)] [] [.parentEntry .derivation (2, 0) .keyed true] = none := by
  decide

/-- S12: obtained after the last consumption. -/
example : insertionFinding 1 [(2, 0)] [] [.consume .derivation,
    .parentEntry .derivation (2, 0) .keyed false] = some .failedCheck := by decide

/-- S13: the entry satisfies the cross-row consistency check. -/
example : insertionFinding 1 [(2, 0)] [] [.parentEntry .derivation (2, 0) .keyed true] =
    some .failedCheck := by decide

/-- S14: an unavailable read first. -/
example : insertionFinding 1 [(2, 0)] [] [.unavailable,
    .parentEntry .derivation (2, 0) .keyed false] = some .unavailableRead := by decide

/-- S14: the failing obtain first. -/
example : insertionFinding 1 [(2, 0)] [] [.parentEntry .derivation (2, 0) .keyed false,
    .unavailable] = some .failedCheck := by decide

/-- S15: the sequence ends before the failing obtain. -/
example : insertionFinding 1 [(2, 0)] [] [.parentAbsent .derivation (3, 0), .consume .derivation] =
    none := by decide

/-- S16: the baseline outcome on a sequence whose entry satisfies every cross-row relation. -/
example : baselineFinding [.parentEntry .derivation (2, 0) .keyed true] = none := by decide

/-- S16: the outcome with E4 on the same sequence. -/
example : insertionFinding 1 [(2, 0)] [] [.parentEntry .derivation (2, 0) .keyed true] =
    some .failedCheck := by decide

/-- S16: equal results on a sequence with no failing event (baseline). -/
example : baselineFinding [.parentAbsent .derivation (2, 0), .unavailable] =
    some .unavailableRead := by decide

/-- S16: equal results on a sequence with no failing event (with E4). -/
example : insertionFinding 1 [(2, 0)] [] [.parentAbsent .derivation (2, 0), .unavailable] =
    some .unavailableRead := by decide

/-- S17: the premise-breaking coinbase of block 1 of the T8 chain inserts `(2, 0)`. -/
example : spendKeys tidB c1 = [(2, 0)] := by decide

/-- S17: the S1 sequence alone gives a failed check. -/
example : insertionFinding 1 (spendKeys tidB c1) []
    [.parentEntry .derivation (2, 0) .keyed false, .consume .derivation] = some .failedCheck := by
  decide

/-- S17: with the `noResult` of block 1 the S1 sequence has no outcome. -/
example : storeOutcome ((applyChain tidB t8).getD 1 .invalid) 1 (spendKeys tidB c1) []
    [.parentEntry .derivation (2, 0) .keyed false, .consume .derivation] = .noOutcome := by
  decide

/-- S17: with the `valid` result of block 0 the empty sequence gives no finding. -/
example : storeOutcome ((applyChain tidB t8).getD 0 .invalid) 0 (spendKeys tidB c0) [] [] =
    .noFinding := by decide

/-- S17: under the injective `tidA` every block of the T8 chain is `valid`. -/
example : applyChain tidA t8 =
    [.valid [(4, 0)], .valid [(4, 0), (2, 0)], .valid [(4, 0), (2, 0), (3, 0)]] := by decide

/-- S17: under `tidA` the `valid` result of block 1 gives the failed check. -/
example : storeOutcome ((applyChain tidA t8).getD 1 .invalid) 1 (spendKeys tidA c1) []
    [.parentEntry .derivation (2, 0) .keyed true] = .finding .failedCheck := by decide

/-- Hostile: an empty block is `invalid`. -/
example : applyChain tidA [[]] = [.invalid] := by decide

/-- Hostile: a constant identifier breaks the premise at the second application. -/
example : applyChain (fun _ => 0) [[cbTx c0], [cbTx c1]] = [.valid [(0, 0)], .noResult] := by
  decide

/-- Hostile: one input listed twice passes `R1` and the removal is idempotent. The
specification rejects such a transaction by the duplicate-outpoint scan, which the model does
not represent. -/
example : applyChain tidA [[cbTx c0, spTx dupIn]] = [.valid [(13, 0)]] := by decide

/-- Hostile: an outpoint listed twice in `ins`. -/
example : insertionFinding 1 [(2, 0), (2, 0)] [] [.parentEntry .derivation (2, 0) .keyed true] =
    some .failedCheck := by decide

/-- Hostile: the outpoint once in `ins` and listed twice in `resolved`. -/
example : insertionFinding 1 [(2, 0)] [(2, 0), (2, 0)]
    [.parentEntry .derivation (2, 0) .keyed true] = none := by decide

/-- Hostile: the block result `invalid` given to `storeOutcome`, a value outside the states of
the rule, since an earlier consensus error ends later reads. -/
example : storeOutcome .invalid 1 [(2, 0)] []
    [.parentEntry .derivation (2, 0) .keyed false, .consume .derivation] =
    .finding .failedCheck := by decide

end Examples

end RubinFormal.OutpointInsertionV1
