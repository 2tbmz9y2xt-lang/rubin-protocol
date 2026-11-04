import Std

/-!
Bounded accounting/result model of proposed spec PR 441 at
500dbe9dc58351832847fa1da4492110c4535996: CANONICAL §§4,13,18,23,25 and
CONSENSUS_STATE_MACHINE §§2,2.5. This is not a live-client or root-byte proof.
Inputs supply earlier validation, startup-validated registry selection, complete
read/integrity outcomes, and the result of comparing the independently derived
root. Uniqueness, spendability, completeness, creation validity, and correspondence
to real outpoints are premises. No database, cryptography, or publication occurs.
-/

namespace RubinFormal
namespace StateConsensusV1

abbrev Height := Fin 4294967296

/-- A run denotes `count` distinct consecutive keys with the same entry shape.
Concatenated runs have disjoint ordinal keys; their union is the complete supplied
final spendable map. This finite size abstraction avoids materializing billions
of equal-sized entries in cap examples. It does not implement UTXO membership. -/
structure EntryRun where
  count : Nat
  covenantDataLength : Fin 65537
deriving Repr, DecidableEq

abbrev StateMap := List EntryRun

def compactSizeLength (n : Nat) : Nat :=
  if n < 253 then 1 else if n < 65536 then 3
  else if n < 4294967296 then 5 else 9

def stateEntryBytes (dataLength : Fin 65537) : Nat :=
  55 + compactSizeLength dataLength.val + dataLength.val

def logicalStateBytes : StateMap → Nat
  | [] => 0
  | run :: rest => run.count * stateEntryBytes run.covenantDataLength + logicalStateBytes rest

inductive Direction where
  | Forward | Disconnect | RestoreOld | LagPrimitive
deriving Repr, DecidableEq

inductive CapSelection where
  | Inactive | Active
deriving Repr, DecidableEq

/-- Invalid registries are rejected by startup, outside this input domain. -/
inductive RegistrySelection where
  | Empty | Unmatched | Matching (activationHeight : Height)
deriving Repr, DecidableEq

def selectCap (registry : RegistrySelection) (height : Height) : CapSelection :=
  match registry with
  | .Empty | .Unmatched => .Inactive
  | .Matching activation => if height.val < activation.val then .Inactive else .Active

/-- The three named earlier outcomes in this bounded model; all other upstream
transaction/block errors and the §19.2 genesis exception remain supplied owners. -/
inductive EarlierError where
  | TX_ERR_MISSING_UTXO | TX_ERR_VALUE_CONSERVATION | BLOCK_ERR_SUBSIDY_EXCEEDED
deriving Repr, DecidableEq

inductive EarlierResult where
  | Passed | Failed (error : EarlierError)
deriving Repr, DecidableEq

inductive ConsensusError where
  | Earlier (error : EarlierError)
  | BLOCK_ERR_STATE_CAP_EXCEEDED | BLOCK_ERR_STATE_GROWTH_EXCEEDED
  | BLOCK_ERR_UTXO_ROOT_MISMATCH
deriving Repr, DecidableEq

inductive RequiredReadKind where
  | ParentTotal | ParentCount | Candidate | Root
deriving Repr, DecidableEq

inductive NoValidityKind where
  | STORE_INTEGRITY | Unavailable (kind : RequiredReadKind) | LOCAL_INVARIANT
deriving Repr, DecidableEq

inductive ParentRead where
  | Ready | AbsentTotal | AbsentCount | UnavailableTotal | UnavailableCount
  | Malformed | Inconsistent
deriving Repr, DecidableEq

inductive CandidateRead where
  | Ready | Unavailable | Malformed | Inconsistent
deriving Repr, DecidableEq

inductive ArithmeticCheck where
  | Consistent | Contradiction
deriving Repr, DecidableEq

inductive RootRead where
  | Equal | Mismatch | Unavailable | Malformed | Inconsistent | MissingCommitted
deriving Repr, DecidableEq

inductive Outcome where
  | Accepted | ConsensusError (error : ConsensusError) | NoValidity (kind : NoValidityKind)
deriving Repr, DecidableEq

inductive Stage where
  | Earlier | Accounting | Cap | Growth | Root
deriving Repr, DecidableEq

structure Input where
  height : Height
  registry : RegistrySelection
  earlier : EarlierResult
  parent : StateMap
  candidate : StateMap
  parentRead : ParentRead
  candidateRead : CandidateRead
  arithmetic : ArithmeticCheck
  root : RootRead
deriving Repr, DecidableEq

/-- Integrity and consistency are supplied read classifications, not a proof of
the concrete §2.5 cross-row check. Its original structural bounds remain outside
this model; in particular no `height * 773120` integrity bound is introduced. -/
def parentReadResult : ParentRead → Except NoValidityKind Unit
  | .Ready => .ok ()
  | .AbsentTotal | .AbsentCount | .Malformed | .Inconsistent => .error .STORE_INTEGRITY
  | .UnavailableTotal => .error (.Unavailable .ParentTotal)
  | .UnavailableCount => .error (.Unavailable .ParentCount)

def candidateReadResult : CandidateRead → Except NoValidityKind Unit
  | .Ready => .ok ()
  | .Malformed | .Inconsistent => .error .STORE_INTEGRITY
  | .Unavailable => .error (.Unavailable .Candidate)

def accounting (i : Input) : Except NoValidityKind (Nat × Nat) := do
  if i.height.val != 0 then parentReadResult i.parentRead else pure ()
  candidateReadResult i.candidateRead
  match i.arithmetic with
  | .Contradiction => throw .LOCAL_INVARIANT
  | .Consistent =>
      let parent := if i.height.val = 0 then [] else i.parent
      pure (logicalStateBytes parent, logicalStateBytes i.candidate)

def CapRule (cap : CapSelection) (s0 s1 : Nat) : Prop :=
  match cap with
  | .Inactive => True
  | .Active => if s0 ≤ 1649267441664 then s1 ≤ 1649267441664 else s1 ≤ s0

instance (cap : CapSelection) (s0 s1 : Nat) : Decidable (CapRule cap s0 s1) := by
  cases cap <;> unfold CapRule <;> infer_instance

structure Observation where
  result : Option Outcome
  reached : List Stage
  parentRequested : Bool
  comparisonEligible : Bool
  candidate : Option StateMap
  canonicalPublished : Bool
deriving Repr, DecidableEq

/-- This boundary can release a private candidate only for later comparison. -/
def observe (candidate : StateMap) (reached : List Stage) (parentRequested : Bool)
    (result : Outcome) : Observation :=
  { result := some result, reached := reached, parentRequested := parentRequested,
    comparisonEligible := match result with | .Accepted => true | _ => false,
    candidate := match result with | .Accepted => some candidate | _ => none,
    canonicalPublished := false }

def capStages (cap : CapSelection) : List Stage :=
  [.Earlier, .Accounting] ++ match cap with | .Inactive => [] | .Active => [.Cap]

/-- Mathematical `s1 ≤ s0 + 773120` is the signed-difference growth rule, so a
shrink cannot underflow. This scalar owner is also exercised on arithmetic
envelopes that need not be realizable maps (notably 100 → 50). -/
def afterAccounting (cap : CapSelection) (s0 s1 : Nat) (root : RootRead)
    (candidate : StateMap) (parentRequested : Bool) : Observation :=
  if CapRule cap s0 s1 then
    if s1 ≤ s0 + 773120 then
      let reached := capStages cap ++ [.Growth, .Root]
      match root with
      | .Equal => observe candidate reached parentRequested .Accepted
      | .Mismatch => observe candidate reached parentRequested
          (.ConsensusError .BLOCK_ERR_UTXO_ROOT_MISMATCH)
      | .Unavailable => observe candidate reached parentRequested (.NoValidity (.Unavailable .Root))
      | .Malformed | .Inconsistent | .MissingCommitted =>
          observe candidate reached parentRequested (.NoValidity .STORE_INTEGRITY)
    else observe candidate (capStages cap ++ [.Growth]) parentRequested
      (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED)
  else observe candidate (capStages cap) parentRequested
    (.ConsensusError .BLOCK_ERR_STATE_CAP_EXCEEDED)

def evaluateForward (i : Input) : Observation :=
  match i.earlier with
  | .Failed error => observe i.candidate [.Earlier] false (.ConsensusError (.Earlier error))
  | .Passed =>
      let cap := selectCap i.registry i.height
      let requested := i.height.val != 0
      match accounting i with
      | .error kind => observe i.candidate [.Earlier, .Accounting] requested (.NoValidity kind)
      | .ok (s0, s1) => afterAccounting cap s0 s1 i.root i.candidate requested

/-- Inverse/LAG operations do not obtain a forward-validity result here. Their
own root/equality/integrity checks remain with the local inverse/LAG owner. -/
def evaluate (direction : Direction) (i : Input) : Observation :=
  match direction with
  | .Forward => evaluateForward i
  | .Disconnect | .RestoreOld | .LagPrimitive =>
      { result := none, reached := [], parentRequested := false,
        comparisonEligible := false, candidate := none, canonicalPublished := false }

def SuccessConditions (i : Input) : Prop :=
  i.earlier = .Passed ∧ ∃ s0 s1, accounting i = .ok (s0, s1) ∧
    CapRule (selectCap i.registry i.height) s0 s1 ∧
    s1 ≤ s0 + 773120 ∧ i.root = .Equal

/-- Exact first reached result, including which later comparisons are absent. -/
def FirstResult (i : Input) (r : Observation) : Prop :=
  match i.earlier with
  | .Failed error => r.result = some (.ConsensusError (.Earlier error)) ∧ r.reached = [.Earlier]
  | .Passed =>
      match accounting i with
      | .error kind => r.result = some (.NoValidity kind) ∧ r.reached = [.Earlier, .Accounting]
      | .ok (s0, s1) =>
          let cap := selectCap i.registry i.height
          if CapRule cap s0 s1 then
            if s1 ≤ s0 + 773120 then
              r.reached = capStages cap ++ [.Growth, .Root] ∧
              r.result = some (match i.root with
                | .Equal => .Accepted
                | .Mismatch => .ConsensusError .BLOCK_ERR_UTXO_ROOT_MISMATCH
                | .Unavailable => .NoValidity (.Unavailable .Root)
                | .Malformed | .Inconsistent | .MissingCommitted => .NoValidity .STORE_INTEGRITY)
            else r.result = some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) ∧
              r.reached = capStages cap ++ [.Growth]
          else r.result = some (.ConsensusError .BLOCK_ERR_STATE_CAP_EXCEEDED) ∧
            r.reached = capStages cap

/-- Registered MODEL theorem: actual evaluator branches imply exact success
conditions, first-result order and candidate release; every refusal releases
nothing. It neither proves input premises nor canonical preference/publication. -/
theorem state_consensus_contract (i : Input) :
    let r := evaluate .Forward i
    (r.result = some .Accepted ↔ SuccessConditions i) ∧
    (r.comparisonEligible = true ↔ r.result = some .Accepted) ∧
    (r.candidate = some i.candidate ↔ r.result = some .Accepted) ∧
    (r.result ≠ some .Accepted → r.candidate = none ∧ r.comparisonEligible = false) ∧
    r.canonicalPublished = false ∧ FirstResult i r := by
  cases hEarlier : i.earlier with
  | Failed error =>
      simp [evaluate, evaluateForward, hEarlier, observe, SuccessConditions, FirstResult]
  | Passed =>
      cases hAccounting : accounting i with
      | error kind =>
          simp [evaluate, evaluateForward, hEarlier, hAccounting, observe,
            SuccessConditions, FirstResult]
      | ok totals =>
          rcases totals with ⟨s0, s1⟩
          by_cases hCap : CapRule (selectCap i.registry i.height) s0 s1
          · by_cases hGrowth : s1 ≤ s0 + 773120
            · cases hRoot : i.root <;>
                simp [evaluate, evaluateForward, hEarlier, hAccounting, afterAccounting,
                  hCap, hGrowth, hRoot, observe, SuccessConditions, FirstResult]
              exact ⟨s0, s1, ⟨rfl, rfl⟩, hCap, hGrowth⟩
            · simp [evaluate, evaluateForward, hEarlier, hAccounting, afterAccounting,
                hCap, hGrowth, observe, SuccessConditions, FirstResult]
          · simp [evaluate, evaluateForward, hEarlier, hAccounting, afterAccounting,
              hCap, observe, SuccessConditions, FirstResult]

structure SuffixObservation where
  result : Option Outcome
  steps : List Observation
  comparisonCandidate : Option StateMap
  canonicalAfter : StateMap
  retryable : Bool
deriving Repr, DecidableEq

/-- Heights/ancestry are prevalidated. Each accepted candidate becomes the exact
next parent; refusal stops the fold. IMAGE import itself is not a forward step.
Even a fully successful suffix leaves the supplied canonical map unchanged. -/
def runSuffix (canonical parent : StateMap) : List Input → SuffixObservation
  | [] => { result := some .Accepted, steps := [], comparisonCandidate := some parent,
            canonicalAfter := canonical, retryable := false }
  | i :: rest =>
      let r := evaluate .Forward { i with parent := parent }
      match r.candidate with
      | none => { result := r.result, steps := [r], comparisonCandidate := none,
                  canonicalAfter := canonical,
                  retryable := match r.result with | some (.NoValidity _) => true | _ => false }
      | some next =>
          let tail := runSuffix canonical next rest
          { tail with steps := r :: tail.steps }

/- Finite, source-derived distinguishing cases. They are not registry theorems.
`sized` is a private fixture of individually bounded shapes, never evaluator
input totals: for each used n ≥ 56 it describes a complete map of exactly n bytes. -/
private def run (count : Nat) (dataLength : Fin 65537) : EntryRun :=
  ⟨count, dataLength⟩

private def sized (n : Nat) : StateMap :=
  if n = 0 then [] else if n % 56 = 0 then [run (n / 56) 0] else
    [run (n / 56 - 1) 0,
     run 1 ⟨n % 56, Nat.lt_trans (Nat.mod_lt n (show 0 < 56 by decide))
       (show 56 < 65537 by decide)⟩]

private def input (s0 s1 : Nat) : Input :=
  { height := ⟨3000000, by decide⟩, registry := .Empty, earlier := .Passed,
    parent := sized s0, candidate := sized s1, parentRead := .Ready,
    candidateRead := .Ready, arithmetic := .Consistent, root := .Equal }

private def active (s0 s1 : Nat) : Input :=
  { input s0 s1 with registry := .Matching ⟨3000000, by decide⟩ }

private def result (i : Input) : Option Outcome := (evaluate .Forward i).result

private def effects (r : Observation) :
    Option Outcome × List Stage × Bool × Bool × Option StateMap × Bool :=
  (r.result, r.reached, r.parentRequested, r.comparisonEligible, r.candidate, r.canonicalPublished)

-- C01: constants and each startup-selected cap branch/height boundary.
example : 755 * 1024 = 773120 ∧ 3 * 2^39 = 1649267441664 := by decide
example : selectCap .Empty ⟨0, by decide⟩ = .Inactive ∧
    selectCap .Unmatched ⟨1001, by decide⟩ = .Inactive := by decide
example : [selectCap (.Matching ⟨1000, by decide⟩) ⟨999, by decide⟩,
    selectCap (.Matching ⟨1000, by decide⟩) ⟨1000, by decide⟩,
    selectCap (.Matching ⟨1000, by decide⟩) ⟨1001, by decide⟩] =
    [.Inactive, .Active, .Active] := by decide
example : selectCap (.Matching ⟨0, by decide⟩) ⟨0, by decide⟩ = .Active := by decide
example : result { input 1000000 1773121 with registry := .Unmatched } =
    some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) ∧
    result { input 1000000 1773121 with
      height := ⟨999, by decide⟩, registry := .Matching ⟨1000, by decide⟩ } =
    some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) := by decide

-- C02: CompactSize boundaries and complete final-map membership abstraction.
example : ([0, 252, 253, 65535, 65536] : List (Fin 65537)).map stateEntryBytes =
    [56, 308, 311, 65593, 65596] := by decide
example : logicalStateBytes [run 1 33] = 89 ∧ logicalStateBytes [] = 0 := by decide

-- C03: exact growth/equality, shrink, and no credit carried from a predecessor.
example : result (input 1000000 1773120) = some .Accepted := by decide
example : (evaluate .Forward (input 1000000 1773121)).reached =
    [.Earlier, .Accounting, .Growth] ∧ result (input 1000000 1773121) =
    some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) := by decide
example : (afterAccounting .Inactive 100 50 .Equal [] true).result = some .Accepted := by decide
example : result (input 100 56) = some .Accepted := by decide
example :
    let r := runSuffix [] (sized 10000000)
      [input 10000000 9000000, { input 9000000 9773121 with height := ⟨3000001, by decide⟩ }]
    r.steps.map (fun step => step.result) =
      [some .Accepted, some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED)] ∧
    r.result = some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) := by decide

-- C04: active cap equality/drain; oversize parents model delayed activation at
-- this height, not an oversize state produced under an always-active cap.
example : result (active 1649267441575 1649267441664) = some .Accepted ∧
    result (active 1649267441575 1649267441665) =
      some (.ConsensusError .BLOCK_ERR_STATE_CAP_EXCEEDED) := by decide
example : result (active 1649267441664 1649267441664) = some .Accepted ∧
    result (active 1649267441664 1649267441665) =
      some (.ConsensusError .BLOCK_ERR_STATE_CAP_EXCEEDED) := by decide
example : result (active 1649272441664 1649272441664) = some .Accepted ∧
    result (active 1649272441664 1649272441663) = some .Accepted ∧
    result (active 1649272441664 1649272441665) =
      some (.ConsensusError .BLOCK_ERR_STATE_CAP_EXCEEDED) := by decide
example : result (input 1649272441664 1649273214784) = some .Accepted ∧
    result (input 1649272441664 1649273214785) =
      some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) := by decide

-- C05: a spent parent entry plus a bounded complete final map; no gross field.
example : logicalStateBytes (sized 773209) = 773209 ∧
    accounting (input 89 773209) = .ok (89, 773209) ∧
    result (input 89 773209) = some .Accepted := by
  constructor
  · rfl
  · constructor <;> rfl
-- A further retained entry must count; an absent created-then-spent entry is
-- not a member of the supplied final map. Transaction history is not an input.
example : logicalStateBytes (run 1 33 :: sized 773209) = 773298 ∧
    result { input 89 773209 with candidate := run 1 33 :: sized 773209 } =
    some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) := by decide

-- C06: absent versus unavailable totals/counts, integrity before arithmetic.
example : [ParentRead.AbsentTotal, .AbsentCount].map (fun p =>
    effects (evaluate .Forward { input 89 89 with height := ⟨1, by decide⟩, parentRead := p })) =
    [(some (.NoValidity .STORE_INTEGRITY), [.Earlier, .Accounting], true, false, none, false),
     (some (.NoValidity .STORE_INTEGRITY), [.Earlier, .Accounting], true, false, none, false)] := by rfl
example : result { input 89 89 with height := ⟨1, by decide⟩, parentRead := .UnavailableTotal } =
    some (.NoValidity (.Unavailable .ParentTotal)) ∧
    result { input 89 89 with height := ⟨1, by decide⟩, parentRead := .UnavailableCount } =
    some (.NoValidity (.Unavailable .ParentCount)) := by decide
example : [ParentRead.Malformed, .Inconsistent].map (fun p =>
    result { input 89 89 with parentRead := p, arithmetic := .Contradiction }) =
    [some (.NoValidity .STORE_INTEGRITY), some (.NoValidity .STORE_INTEGRITY)] := by decide
example : result { input 89 89 with arithmetic := .Contradiction } =
    some (.NoValidity .LOCAL_INVARIANT) := by decide
example : [CandidateRead.Unavailable, .Malformed, .Inconsistent].map (fun c =>
    result { input 89 89 with candidateRead := c, arithmetic := .Contradiction }) =
    [some (.NoValidity (.Unavailable .Candidate)), some (.NoValidity .STORE_INTEGRITY),
     some (.NoValidity .STORE_INTEGRITY)] := by decide
example : result { input 89 89 with
    earlier := .Failed .TX_ERR_MISSING_UTXO, parentRead := .AbsentTotal } =
    some (.ConsensusError (.Earlier .TX_ERR_MISSING_UTXO)) := by decide

-- C07: exact first result, reachability, and no candidate on simultaneous failures.
example : [EarlierError.TX_ERR_VALUE_CONSERVATION, .BLOCK_ERR_SUBSIDY_EXCEEDED].map
    (fun e => effects (evaluate .Forward { active 1649267441664 1649268214785 with
      earlier := .Failed e, parentRead := .Malformed, root := .Unavailable })) =
    [(some (.ConsensusError (.Earlier .TX_ERR_VALUE_CONSERVATION)), [.Earlier], false, false, none, false),
     (some (.ConsensusError (.Earlier .BLOCK_ERR_SUBSIDY_EXCEEDED)), [.Earlier], false, false, none, false)] := by rfl
example : effects (evaluate .Forward { active 1649267441664 1649268214785 with parentRead := .Malformed }) =
    (some (.NoValidity .STORE_INTEGRITY), [.Earlier, .Accounting], true, false, none, false) := by rfl
example : [RootRead.Mismatch, .Unavailable].map (fun root =>
    effects (evaluate .Forward { active 1649267441664 1649268214785 with root := root })) =
    [(some (.ConsensusError .BLOCK_ERR_STATE_CAP_EXCEEDED), [.Earlier, .Accounting, .Cap], true, false, none, false),
     (some (.ConsensusError .BLOCK_ERR_STATE_CAP_EXCEEDED), [.Earlier, .Accounting, .Cap], true, false, none, false)] := by rfl
example : [RootRead.Mismatch, .Unavailable].map (fun root =>
    effects (evaluate .Forward { input 1000000 1773121 with root := root })) =
    [(some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED), [.Earlier, .Accounting, .Growth], true, false, none, false),
     (some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED), [.Earlier, .Accounting, .Growth], true, false, none, false)] := by rfl
example : result { input 1000000 1773120 with root := .Mismatch } =
    some (.ConsensusError .BLOCK_ERR_UTXO_ROOT_MISMATCH) ∧
    result { input 1000000 1773120 with root := .Unavailable } =
    some (.NoValidity (.Unavailable .Root)) := by decide
example : [RootRead.Malformed, .Inconsistent, .MissingCommitted].map (fun r =>
    result { input 89 89 with root := r }) =
    [some (.NoValidity .STORE_INTEGRITY), some (.NoValidity .STORE_INTEGRITY),
     some (.NoValidity .STORE_INTEGRITY)] := by decide
example : (evaluate .Forward { input 89 773210 with root := .Unavailable }).candidate = none ∧
    (evaluate .Forward { input 89 773210 with root := .Unavailable }).comparisonEligible = false ∧
    (evaluate .Forward (input 89 773209)).comparisonEligible = true ∧
    (evaluate .Forward (input 89 773209)).canonicalPublished = false := by decide

-- C08: unique empty genesis parent, no persisted parent request or growth exemption.
private def genesis (lastDataLength : Fin 65537) : Input :=
  { active 10000000 0 with
    height := ⟨0, by decide⟩, parentRead := .AbsentTotal,
    registry := .Matching ⟨0, by decide⟩, candidate := [run 11 65536, run 1 lastDataLength] }
example : accounting { input 10000000 89 with
    height := ⟨0, by decide⟩, parentRead := .UnavailableCount } = .ok (0, 89) ∧
    (evaluate .Forward { input 10000000 89 with
      height := ⟨0, by decide⟩, parentRead := .Malformed }).parentRequested = false := by
  constructor <;> rfl
example : result { input 10000000 89 with
    height := ⟨0, by decide⟩, registry := .Matching ⟨0, by decide⟩,
    parentRead := .AbsentCount } = some .Accepted := by decide
example : logicalStateBytes (genesis 51506).candidate = 773120 ∧
    result (genesis 51506) = some .Accepted ∧
    logicalStateBytes (genesis 51507).candidate = 773121 ∧
    result (genesis 51507) = some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) := by decide

-- C09: exact evolving parents, imported base, first refusal, retry, no publication.
example :
    let r := runSuffix (sized 89) (sized 10000000)
      [input 0 9000000, { input 0 9773121 with height := ⟨3000001, by decide⟩ },
       { input 0 89 with height := ⟨3000002, by decide⟩, root := .Mismatch }]
    r.result = some (.ConsensusError .BLOCK_ERR_STATE_GROWTH_EXCEEDED) ∧
    r.steps.length = 2 ∧ r.comparisonCandidate = none ∧ r.canonicalAfter = sized 89 := by decide
example :
    let r := runSuffix (sized 89) (sized 10000000) [input 0 10773120]
    r.result = some .Accepted ∧ r.comparisonCandidate = some (sized 10773120) ∧
    r.canonicalAfter = sized 89 := by decide
example :
    let r := runSuffix (sized 89) (sized 10000000)
      [input 0 9000000, { input 0 9773120 with height := ⟨3000001, by decide⟩ }]
    r.result = some .Accepted ∧ r.comparisonCandidate = some (sized 9773120) ∧
    r.steps.length = 2 ∧ r.canonicalAfter = sized 89 := by decide
example :
    let r := runSuffix (sized 89) (sized 10000000)
      [{ input 0 10000000 with root := .Unavailable },
       { input 0 89 with height := ⟨3000001, by decide⟩ }]
    r.result = some (.NoValidity (.Unavailable .Root)) ∧ r.retryable = true ∧
    r.steps.length = 1 ∧ r.comparisonCandidate = none ∧ r.canonicalAfter = sized 89 := by decide

-- C10: forward shrink succeeds; each inverse direction stays outside this validator.
example : result (input 10000000 9000000) = some .Accepted := by decide
example : [Direction.Disconnect, .RestoreOld, .LagPrimitive].map (fun d =>
    evaluate d { active 9000000 10000000 with parentRead := .Malformed, root := .Mismatch }) =
    List.replicate 3 ({
      result := none, reached := [], parentRequested := false,
      comparisonEligible := false, candidate := none, canonicalPublished := false } : Observation) := by rfl

end StateConsensusV1
end RubinFormal
