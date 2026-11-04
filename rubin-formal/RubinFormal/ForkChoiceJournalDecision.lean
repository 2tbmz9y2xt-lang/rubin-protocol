import RubinFormal.ForkChoiceSelect

/-!
Finite ordinary-consumer model of proposed rubin-spec#441@500dbe9dc58351832847fa1da4492110c4535996,
CANONICAL §23 and MEMPOOL §6.4.1.4. Header/path/source qualifications below are
explicit abstract premises, not proofs of their acquisition or authenticity.
The additional assertions are unregistered evidence, not a §23/client proof.
-/
namespace RubinFormal.JournalChoice

open ForkChoiceV1

structure Point where
  height : Nat
  hash : List UInt8
deriving BEq, DecidableEq, Repr

structure Tip where
  point : Point
  work : Nat
deriving BEq, DecidableEq, Repr

/-- Strict rank deliberately excludes forkSelect's equal-value Left fallback. -/
def strictlyOutranks (a b : Tip) : Bool :=
  a.point.hash.length == 32 && b.point.hash.length == 32 &&
    (a.work > b.work || (a.work == b.work && bytesLT a.point.hash b.point.hash))

structure Context where
  network : Nat
  genesis : Nat
  chainId : Nat
  law : Nat
  history : Nat
  release : Nat
deriving BEq, DecidableEq, Repr

structure Original where
  context : Context
  base : Point
  root : Nat
  target : Tip
  pin : Point
  minimumWork : Nat
  appliedLagBase : Nat
  completeCurrent : Option Nat
  completeLag : Option Nat
  headerPath : List Point
  headersQualified : Bool
  imageEntry : Bool
  imageCover : Bool
  historicalMembership : Bool
  bothSeedCorrespondence : Bool
  rootIdentityMetadata : Bool
  originalTailValidated : Bool
  originalPairComplete : Bool
  selected : Bool
deriving BEq, DecidableEq, Repr

private def referencePresent : Option Nat → Bool
  | some _ => true -- Abstract identifiers have no reserved numeric encoding.
  | none => false

/-- The zero-debt Phi at original H0; PRE_GENESIS has no conditional base. -/
def appliedBaseHeight (height : Nat) : Option Nat :=
  if height < 15120 then none else some (720 * ((height - 15120) / 720))

/-- COMPLETE supplies the authenticated base before the whole IMAGE tail succeeds. -/
def originalSourceQualified (ctx : Context) (o : Original) : Bool :=
  o.context == ctx && referencePresent o.completeCurrent && referencePresent o.completeLag &&
  o.headersQualified && o.headerPath.all (fun p => p.hash.length == 32) &&
  o.headerPath.contains o.pin && o.headerPath.contains o.base &&
  o.headerPath.contains o.target.point && o.pin.height <= o.target.point.height &&
  appliedBaseHeight o.target.point.height == some o.base.height &&
  appliedBaseHeight o.target.point.height == some o.appliedLagBase && o.target.work >= o.minimumWork &&
  o.imageEntry && o.imageCover && o.historicalMembership && o.bothSeedCorrespondence &&
  o.rootIdentityMetadata

def originalQualified (ctx : Context) (o : Original) : Bool :=
  originalSourceQualified ctx o && o.originalTailValidated && o.originalPairComplete

structure Continuation where
  common : Tip
  reconstructedPrefix : Bool
  actualState : Bool
  undoSources : Bool
  bodySources : Bool
  suffixSection25 : Bool
deriving BEq, DecidableEq, Repr

inductive Provenance where
  | headerOnly
  | fullHistory (genesisToTip : Bool)
  | initial (original : Original)
  | continued (original : Original) (continuation : Continuation)
deriving BEq, DecidableEq, Repr

inductive Assurance where
  | fullHistory
  | conditionalImportedBase
deriving BEq, DecidableEq, Repr

/-- Opaque source observation; fixture labels define no public error tokens. -/
structure Refusal where
  owner : Nat
  error : String
  cause : String
  latch : Nat
  rawTruth : Nat
  disposition : Nat
deriving BEq, DecidableEq, Repr

structure Candidate where
  id : Nat
  tip : Tip
  context : Context
  path : List Point
  pathComplete : Bool
  headerRules : Bool
  actualWork : Bool
  requiredSources : Bool
  provenance : Provenance
  refusal : Refusal
deriving BEq, DecidableEq, Repr

def headerQualified (ctx : Context) (c : Candidate) : Bool :=
  c.context == ctx && c.pathComplete && c.headerRules && c.actualWork && c.requiredSources &&
  c.tip.point.hash.length == 32 && c.path.all (fun p => p.hash.length == 32) &&
  c.path.contains c.tip.point

def stateQualified (ctx : Context) (c : Candidate) : Bool :=
  match c.provenance with
  | .headerOnly => false
  | .fullHistory validated => validated
  | .initial o => originalQualified ctx o && c.tip == o.target && c.path == o.headerPath
  | .continued o k =>
      originalQualified ctx o && o.selected && k.common.point.height >= o.base.height &&
      k.common.point.height <= c.tip.point.height && c.path.contains k.common.point &&
      c.path.contains o.base && c.path.contains o.pin && c.tip.work >= o.minimumWork &&
      k.reconstructedPrefix && k.actualState && k.undoSources && k.bodySources && k.suffixSection25

def assurance (c : Candidate) : Assurance :=
  match c.provenance with
  | .initial _ | .continued _ _ => .conditionalImportedBase
  | _ => .fullHistory

inductive Origin where
  | fullHistory (context : Context) (executedParentPath : Bool)
  | conditional (original : Original) (executedParentPath : Bool)
deriving BEq, DecidableEq, Repr

def originQualified (ctx : Context) (block : Point) : Origin → Bool
  | .fullHistory c executed => c == ctx && executed
  | .conditional o executed => originalSourceQualified ctx o && executed && block.height > o.base.height

/-- Original identity excludes later completion and selection observations. -/
def sameOriginalBinding (o p : Original) : Bool :=
  o.context == p.context && o.base == p.base && o.root == p.root && o.target == p.target &&
  o.pin == p.pin && o.minimumWork == p.minimumWork && o.appliedLagBase == p.appliedLagBase &&
  o.completeCurrent == p.completeCurrent && o.completeLag == p.completeLag

def coversOrigin : Origin → Origin → Bool
  | .fullHistory c _, .fullHistory d _ => c == d
  | .conditional o _, .fullHistory c _ => o.context == c
  | .conditional o _, .conditional p _ => sameOriginalBinding o p
  | .fullHistory _ _, .conditional _ _ => false

structure Correction where
  origin : Origin
  executed : Point
  entireParentPath : Bool
  orderedAcceptance : Bool
  retainedSources : Bool
deriving BEq, DecidableEq, Repr

inductive Disposition where
  | activeOriginal
  | corrected (proof : Correction)
deriving BEq, DecidableEq, Repr

inductive Scope where
  | same
  | different
  | unresolved
deriving BEq, DecidableEq, Repr

inductive Health where
  | qualified
  | suspect
  | unresolved
deriving BEq, DecidableEq, Repr

structure Fact where
  block : Point
  origin : Origin
  originalSources : Bool
  scope : Scope
  scopeQualified : Bool
  health : Health
  disposition : Disposition
  refusal : Refusal
deriving BEq, DecidableEq, Repr

inductive NonoperativeKind where
  | reservation
  | audit
  | disposition
deriving BEq, DecidableEq, Repr

inductive Record where
  | rejection (fact : Fact)
  | nonoperative (kind : NonoperativeKind)
  | malformed (refusal : Refusal)
deriving BEq, DecidableEq, Repr

inductive Membership where
  | complete (records : List Record)
  | partialView (refusal : Refusal)
  | unreadable (refusal : Refusal)
deriving BEq, DecidableEq, Repr

inductive Relation where
  | eligible
  | excluded
  | unresolved
deriving BEq, DecidableEq, Repr

def relation (ctx : Context) (path : List Point) (f : Fact) : Relation :=
  if !(path.any (fun p => p.hash == f.block.hash)) then .eligible
  else if !(path.contains f.block) then .unresolved
  else if !f.scopeQualified then .unresolved
  else match f.scope with
    | .unresolved => .unresolved
    | .different =>
        let ownContext := match f.origin with
          | .fullHistory c _ => c
          | .conditional o _ => o.context
        if ownContext.network == ctx.network && ownContext.genesis == ctx.genesis &&
            (ownContext.law != ctx.law || ownContext.history != ctx.history) &&
            ownContext.chainId == ctx.chainId && originQualified ownContext f.block f.origin &&
            f.originalSources && f.health == .qualified
        then .eligible else .unresolved
    | .same => match f.disposition with
      | .activeOriginal =>
          if originQualified ctx f.block f.origin && f.originalSources && f.health == .qualified
          then .excluded else .unresolved
      | .corrected p =>
          if originQualified ctx p.executed p.origin && coversOrigin f.origin p.origin &&
              p.executed == f.block && p.entireParentPath && p.orderedAcceptance && p.retainedSources
          then .eligible else .unresolved

def candidateRelation (ctx : Context) (records : List Record) (c : Candidate) : Relation :=
  let facts := records.filterMap fun r => match r with
    | .rejection f => some f
    | _ => none
  let qualifiedSame := fun (f : Fact) =>
    f.scope == .same && f.scopeQualified && f.originalSources &&
      originQualified ctx f.block f.origin
  let relations := facts.map fun f =>
    if c.path.any (fun p => p.hash == f.block.hash) && facts.any (fun other =>
        other.block.hash == f.block.hash && (other.block.height != f.block.height ||
          (qualifiedSame f && qualifiedSame other &&
            coversOrigin f.origin other.origin && coversOrigin other.origin f.origin &&
            (match f.disposition, other.disposition with
             | .activeOriginal, .corrected _ | .corrected _, .activeOriginal => true
             | _, _ => false))))
    then .unresolved else relation ctx c.path f
  if relations.contains .excluded then .excluded
  else if relations.contains .unresolved then .unresolved else .eligible

inductive Boundary where
  | entry
  | reentry
  | preactivation
  | outerSelection
deriving BEq, DecidableEq, Repr

inductive Domain where
  | headers
  | states (boundary : Boundary)
  | fixedStep (ownComparands : List Nat)
deriving BEq, DecidableEq, Repr

structure Basis where
  context : Context
  installation : Nat
  control : Nat
  membershipVersion : Nat
  originalRevisions : List Nat
  correctiveRevisions : List Nat
  sourceGuards : List Nat
  inventory : Nat
  path : Nat
  target : Nat
  native : Nat
  comparands : Nat
  historicalScope : Nat
deriving BEq, DecidableEq, Repr

inductive OldEvidence where
  | notRequired
  | required (value : Option Candidate)
deriving BEq, DecidableEq, Repr

structure Required where
  old : OldEvidence
  publishedPrefix : Option Candidate
  sources : Bool
  roles : Option Bool
  refusal : Refusal
deriving BEq, DecidableEq, Repr

structure PublicState where
  canonical : Nat
  effects : List Nat
  invalidBranches : List Point
  journalRejections : List Point
deriving BEq, DecidableEq, Repr

structure Request where
  domain : Domain
  basis : Basis
  currentBasis : Basis
  inventory : List Candidate
  scanned : List Candidate
  membership : Membership
  required : Required
  inventoryRefusal : Refusal
  firstObserved : Option Refusal
  nativeDiagnostic : Option Point
  publicState : PublicState
deriving BEq, DecidableEq, Repr

private def unique : List Nat → Bool
  | [] => true
  | n :: ns => !(ns.contains n) && unique ns

private def sameIds (xs ys : List Nat) : Bool :=
  unique xs && unique ys && xs.all ys.contains && ys.all xs.contains

def requiredIds (r : Request) : List Nat :=
  let old := match r.required.old with | .notRequired => none | .required value => value
  let mandatory := ([old, r.required.publishedPrefix].filterMap (fun c => c.map Candidate.id)).eraseDups
  match r.domain with
  | .headers => r.inventory.map Candidate.id
  | .states _ => r.inventory.filterMap fun c => match c.provenance with
      | .headerOnly => none
      | _ => some c.id
  | .fixedStep ids => ids ++ mandatory.filter (fun n => !(ids.contains n))

private def candidateQualified (r : Request) (c : Candidate) : Bool :=
  headerQualified r.currentBasis.context c &&
    (match r.domain with | .headers => true | _ => stateQualified r.currentBasis.context c)

private def requiredQualified (r : Request) : Bool :=
  let qualified := fun (state : Bool) (value : Option Candidate) => match value with
    | none => false
    | some c => headerQualified r.currentBasis.context c &&
        (!state || stateQualified r.currentBasis.context c) &&
        r.inventory.contains c && (requiredIds r).contains c.id
  r.required.sources && match r.domain, r.required.old with
    | .headers, .notRequired => r.required.roles == none && qualified false r.required.publishedPrefix
    | .headers, .required _ => false
    | _, .notRequired => false
    | _, .required old => r.required.roles == some true && qualified true old &&
        qualified true r.required.publishedPrefix

/-- Unordered missing-premise diagnostics retain their supplied source owners;
    a source's already observed first outcome is handled separately. -/
def missingPremises (r : Request) : List Refusal :=
  let membershipFailures := match r.membership with
    | .partialView f | .unreadable f => [f]
    | .complete rs => rs.filterMap fun x => match x with
        | .malformed f => some f
        | .rejection f => if f.block.hash.length == 32 then none else some f.refusal
        | .nonoperative _ => none
  let inventoryOK := sameIds (requiredIds r) (r.scanned.map Candidate.id) &&
    unique (r.inventory.map Candidate.id) && r.scanned.all r.inventory.contains
  membershipFailures ++ (if requiredQualified r then [] else [r.required.refusal]) ++
    (if inventoryOK then [] else [r.inventoryRefusal]) ++
    r.scanned.filterMap (fun c => if candidateQualified r c then none else some c.refusal)

inductive Decision where
  | scheduled (candidate : Nat)
  | selected (candidate : Nat) (assurance : Assurance)
  | indistinguishable (work : Nat) (hash : List UInt8)
  | unavailable
  | missing (sourceDiagnostics : List Refusal)
  | stale
  | observed (first : Refusal)
deriving BEq, DecidableEq, Repr

def decideSelection (r : Request) : Decision :=
  match r.firstObserved with
  | some first => .observed first
  | none =>
    if r.basis != r.currentBasis then .stale
    else if !(missingPremises r).isEmpty then .missing (missingPremises r)
    else
      let records := match r.membership with | .complete rs => rs | _ => []
      let qualified := r.scanned.filter (fun c => candidateRelation r.currentBasis.context records c == .eligible)
      match qualified with
      | [] => .unavailable
      | first :: rest =>
        let winner := rest.foldl (fun w c => if strictlyOutranks c.tip w.tip then c else w) first
        if r.scanned.all (fun u => candidateRelation r.currentBasis.context records u != .unresolved ||
            strictlyOutranks winner.tip u.tip)
        then
          if qualified.any (fun c => c.id != winner.id && c.tip.work == winner.tip.work &&
              c.tip.point.hash == winner.tip.point.hash)
          then .indistinguishable winner.tip.work winner.tip.point.hash
          else match r.domain with
            | .headers => .scheduled winner.id
            | _ => .selected winner.id (assurance winner)
        else .unavailable

structure Evaluation where
  decision : Decision
  retained : Request
deriving BEq, DecidableEq, Repr

/-- Preference is private evidence only. Publication/completion is a separate owner. -/
def evaluate (r : Request) : Evaluation := ⟨decideSelection r, r⟩

-- F01–F24: independent finite expectations, reduced by the kernel, not native_decide.
private def hashA : List UInt8 := [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
private def hashB : List UInt8 := [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]
private def hashC : List UInt8 := [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
private def hashD : List UInt8 := [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
private def hashE : List UInt8 := [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3]
private def hashF : List UInt8 := [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4]
private def hashG : List UInt8 := [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5]
private def ctx : Context := ⟨1,2,3,4,5,6⟩
private def failure : Refusal := ⟨1,"SOURCE_INTEGRITY","original cause",7,8,9⟩
private def inventoryFailure : Refusal := ⟨2,"INVENTORY_UNAVAILABLE","membership",0,3,4⟩
private def base : Point := ⟨720,hashE⟩
private def pin : Point := ⟨2,hashF⟩
private def original : Original :=
  ⟨ctx,base,77,⟨⟨15840,hashC⟩,150⟩,pin,100,720,some 11,some 12,
    [pin,base,⟨15840,hashC⟩],true,true,true,true,true,true,true,true,true⟩
private def continuation : Continuation := ⟨⟨base,30⟩,true,true,true,true,true⟩
private def candidate (id work : Nat) (hash : List UInt8 := hashA)
    (provenance : Provenance := .fullHistory true) : Candidate :=
  ⟨id,⟨⟨726,hash⟩,work⟩,ctx,[pin,base,⟨726,hash⟩],true,true,true,true,provenance,failure⟩
private def old : Candidate := candidate 0 0 hashG
private def basis : Basis := ⟨ctx,1,2,3,[4],[5],[6],7,8,9,10,11,12⟩
private def fact : Fact := ⟨base,.fullHistory ctx true,true,.same,true,.qualified,.activeOriginal,failure⟩
private def uncertain : Fact := { fact with scopeQualified := false }
private def proof : Correction := ⟨.fullHistory ctx true,base,true,true,true⟩
private def request (domain : Domain) (cs : List Candidate) (rs : List Record := []) : Request :=
  let inventory := old :: cs
  let scanned := match domain with
    | .headers => inventory
    | .states _ => inventory.filter (fun c => match c.provenance with | .headerOnly => false | _ => true)
    | .fixedStep ids => inventory.filter (fun c => c.id == 0 || ids.contains c.id)
  let required := match domain with
    | .headers => Required.mk .notRequired (some old) true none failure
    | _ => Required.mk (.required (some old)) (some old) true (some true) failure
  ⟨domain,basis,basis,inventory,scanned,.complete rs,
    required,inventoryFailure,none,none,⟨42,[5],[],[]⟩⟩
private def outcome (r : Request) : Decision := (evaluate r).decision
private def high : Candidate := candidate 1 101
private def low : Candidate := candidate 2 100 hashB
private def unresolvedAt (c : Candidate) : Record := .rejection { uncertain with block := c.tip.point }
private def equalUnresolved (work : Nat) : Candidate :=
  { candidate 2 work with path := [pin,base,⟨722,hashD⟩,⟨726,hashA⟩] }
private def equalFact : Record := .rejection { uncertain with block := ⟨722,hashD⟩ }
private def ordinary : Request := request .headers [high,low] [unresolvedAt low]

-- F01/F03: both dispositions, reversed inventory, defeating work, complete retained input.
example : outcome ordinary = .scheduled 1 ∧
    outcome { ordinary with scanned := ordinary.scanned.reverse } = .scheduled 1 ∧
    outcome { ordinary with membership := .complete [] } = .scheduled 1 ∧
    outcome { ordinary with membership := .complete [.rejection { fact with block := low.tip.point }] } = .scheduled 1 ∧
    (evaluate ordinary).retained = ordinary := by decide
example : outcome (request .headers [candidate 1 100,candidate 2 101 hashB]
    [unresolvedAt (candidate 2 101 hashB)]) = .unavailable := by decide

-- F02/F04: last/first/interior byte order, equality, distinct IDs, existing fallback.
example : outcome (request .headers [candidate 1 9,candidate 2 9 hashB]
    [unresolvedAt (candidate 2 9 hashB)]) = .scheduled 1 ∧
    outcome (request .headers [candidate 1 9 hashB,candidate 2 9]
    [unresolvedAt (candidate 2 9)]) = .unavailable ∧
    outcome (request .headers [candidate 1 9 hashD,candidate 2 9 hashC]
    [unresolvedAt (candidate 2 9 hashC)]) = .scheduled 1 ∧
    outcome (request .headers [candidate 1 9,candidate 2 9 hashD]
    [unresolvedAt (candidate 2 9 hashD)]) = .scheduled 1 ∧
    strictlyOutranks high.tip high.tip = false ∧ forkSelect 9 9 hashA hashA = .Left := by decide
example : outcome (request .headers [high,equalUnresolved 101] [equalFact]) = .unavailable := by decide
example : outcome (request .headers [high,candidate 2 101]) = .indistinguishable 101 hashA ∧
    outcome { request .headers [high,candidate 2 101] with scanned := [candidate 2 101,high,old] } =
      .indistinguishable 101 hashA := by decide

-- F05–F09: all records participate; correction leaves the diagnostic nonoperative.
example : relation ctx high.path { fact with block := ⟨1,hashC⟩, scopeQualified := false } = .eligible ∧
    relation ctx high.path fact = .excluded ∧
    relation ctx high.path { fact with scope := .different } = .unresolved ∧
    relation ctx high.path { fact with scope := .different, scopeQualified := false } = .unresolved ∧
    relation ctx high.path { fact with block := ⟨721,hashE⟩ } = .unresolved := by decide
example : ([Health.suspect,.unresolved] : List Health).all (fun h =>
    relation ctx high.path { fact with health := h } == .unresolved) = true ∧
    relation ctx high.path { fact with scope := .unresolved } = .unresolved ∧
    relation ctx high.path { fact with originalSources := false } = .unresolved := by decide
private def corrected : Record := Record.rejection { fact with disposition := .corrected proof }
example : outcome (request .headers [high] [corrected]) = .scheduled 1 ∧
    outcome { request .headers [high] [corrected] with nativeDiagnostic := some base } = .scheduled 1 ∧
    relation ctx high.path { fact with disposition := .corrected { proof with retainedSources := false } } = .unresolved ∧
    relation ctx (equalUnresolved 101).path { fact with block := ⟨722,hashD⟩, disposition := .corrected { proof with origin := .conditional original true, executed := ⟨722,hashD⟩ } } = .unresolved := by decide
example : relation ctx high.path { fact with health := .suspect, disposition := .corrected proof } = .eligible ∧
    relation ctx high.path { fact with health := .suspect, disposition := .corrected { proof with retainedSources := false } } = .unresolved := by decide
private def reachedOriginal : Original :=
  { original with originalTailValidated := false, originalPairComplete := false, selected := false }
private def reachedFact : Fact := { fact with block := ⟨722,hashD⟩, origin := .conditional reachedOriginal true }
example : relation ctx (equalUnresolved 105).path reachedFact = .excluded ∧
    relation ctx (equalUnresolved 105).path { reachedFact with block := base } = .unresolved ∧
    relation ctx (equalUnresolved 105).path { reachedFact with disposition := .corrected { proof with executed := ⟨722,hashD⟩ } } = .eligible := by decide
example : outcome (request .headers [high,low,candidate 3 102 hashD]
    [unresolvedAt low,unresolvedAt (candidate 3 102 hashD),corrected,
      .nonoperative .reservation,.nonoperative .audit,.nonoperative .disposition]) = .unavailable ∧
    candidateRelation ctx [.rejection uncertain,.rejection fact] high = .excluded := by decide
private def conflicting : List Record := [.rejection fact,.rejection { fact with block := ⟨721,hashE⟩ }]
private def independent : Candidate := { high with path := [pin,high.tip.point] }
private def disputed : Candidate := candidate 2 105 hashB
example : candidateRelation ctx conflicting disputed = .unresolved ∧
    outcome (request .headers [independent,disputed] conflicting) = .unavailable ∧
    outcome (request .headers [independent,disputed]
      (conflicting ++ [.rejection { fact with block := disputed.tip.point }])) = .scheduled 1 := by decide

-- F06–F09: contradictory same-scope acceptance, immutable coverage and own historical law.
private def sameScopeConflict : List Record := [.rejection fact,corrected]
private def lowerIndependent : Candidate := { independent with tip := ⟨independent.tip.point,100⟩ }
private def lostCorrected : Fact := { fact with disposition := .corrected { proof with retainedSources := false } }
private def lostScopeConflict : List Record := [.rejection fact,.rejection lostCorrected]
example :
    ([sameScopeConflict, sameScopeConflict.reverse,
      lostScopeConflict, lostScopeConflict.reverse,
      [.rejection lostCorrected,.rejection lostCorrected]] : List (List Record)).all (fun rs =>
      candidateRelation ctx rs disputed == .unresolved &&
      candidateRelation ctx rs lowerIndependent == .eligible &&
      outcome (request .headers [lowerIndependent,disputed] rs) == .unavailable &&
      outcome (request .headers [lowerIndependent,disputed]
        (rs ++ [.rejection { fact with block := disputed.tip.point }])) == .scheduled 1) = true ∧
    candidateRelation ctx [.rejection fact,.rejection fact] disputed = .excluded ∧
    outcome (request .headers [lowerIndependent,disputed]
      [.rejection fact,.rejection fact]) = .scheduled 1 ∧
    candidateRelation ctx [corrected,corrected] disputed = .eligible ∧
    outcome (request .headers [lowerIndependent,disputed]
      [corrected,corrected]) = .scheduled 2 := by decide
example :
    ([{ lostCorrected with scopeQualified := false },
      { lostCorrected with originalSources := false },
      { lostCorrected with origin := .fullHistory ctx false }] : List Fact).all (fun f =>
      candidateRelation ctx [.rejection fact,.rejection f] disputed == .excluded &&
      outcome (request .headers [lowerIndependent,disputed]
        [.rejection fact,.rejection f]) == .scheduled 1) = true := by decide
private def otherScope : List Record :=
  [.rejection { fact with block := ⟨722,hashD⟩ },
   .rejection { reachedFact with
     disposition := .corrected { proof with
       origin := .conditional reachedOriginal true,
       executed := ⟨722,hashD⟩,
       retainedSources := false } }]
private def tailDisputed : Candidate := { disputed with path := [pin,base,⟨722,hashD⟩,disputed.tip.point] }
example : ([otherScope,otherScope.reverse] : List (List Record)).all (fun rs =>
    candidateRelation ctx rs tailDisputed == .excluded &&
    outcome (request .headers [lowerIndependent,tailDisputed] rs) == .scheduled 1) = true := by decide
private def anotherBase : Original := { original with base := ⟨720,hashG⟩, appliedLagBase := 720, headerPath := [pin,⟨720,hashG⟩,original.target.point] }
example : relation ctx (equalUnresolved 105).path { reachedFact with disposition := .corrected { proof with origin := .conditional original true, executed := ⟨722,hashD⟩ } } = .eligible ∧
    originalSourceQualified ctx anotherBase = true ∧
    relation ctx (equalUnresolved 105).path { reachedFact with disposition := .corrected { proof with origin := .conditional anotherBase true, executed := ⟨722,hashD⟩ } } = .unresolved ∧
    relation ctx (equalUnresolved 105).path { reachedFact with disposition := .corrected { proof with origin := .conditional { original with completeCurrent := some 99 } true, executed := ⟨722,hashD⟩ } } = .unresolved := by decide
private def historical : Context := { ctx with law := 40, history := 50, release := 60 }
private def differentFact : Fact := { fact with origin := .fullHistory historical true, scope := .different }
example : relation ctx disputed.path differentFact = .eligible ∧
    outcome (request .headers [lowerIndependent,disputed] [.rejection differentFact]) = .scheduled 2 ∧
    relation ctx disputed.path { differentFact with scopeQualified := false } = .unresolved ∧
    relation ctx disputed.path { differentFact with origin := .fullHistory historical false } = .unresolved ∧
    relation ctx disputed.path { differentFact with originalSources := false } = .unresolved ∧
    relation ctx (equalUnresolved 105).path { reachedFact with origin := .conditional { reachedOriginal with context := historical } true, scope := .different } = .eligible ∧
    relation ctx (equalUnresolved 105).path { reachedFact with origin := .conditional { reachedOriginal with context := historical, historicalMembership := false } true, scope := .different } = .unresolved := by decide
example : ([ { historical with network := 9 }, { historical with genesis := 9 }, { historical with chainId := 9 } ] : List Context).all (fun otherContext =>
    relation ctx disputed.path { differentFact with origin := .fullHistory otherContext true } == .unresolved) = true := by decide
example : ([ctx,{ ctx with release := 60 }] : List Context).all (fun own =>
    relation ctx disputed.path { differentFact with origin := .fullHistory own true } == .unresolved &&
    outcome (request .headers [lowerIndependent,disputed]
      [.rejection { differentFact with origin := .fullHistory own true }]) == .unavailable) = true := by decide
example : ([{ ctx with law := 40 },{ ctx with history := 50 }] : List Context).all (fun own =>
    relation ctx disputed.path { differentFact with origin := .fullHistory own true } == .eligible &&
    outcome (request .headers [lowerIndependent,disputed]
      [.rejection { differentFact with origin := .fullHistory own true }]) == .scheduled 2) = true := by decide

-- F10–F13: immutable initial E0 versus selected continuation, actual T, no H0 floor.
private def initial : Candidate := { candidate 1 150 hashC (.initial { original with selected := false }) with
  tip := original.target, path := original.headerPath }
private def continued : Candidate := candidate 1 100 hashA (.continued original continuation)
private def reconstructed : Continuation := { continuation with common := ⟨⟨722,hashD⟩,40⟩ }
private def stateRequest (c : Candidate) : Request := request (.states .outerSelection) [c]
example : outcome (stateRequest high) = .selected 1 .fullHistory ∧
    ([initial,continued,
      { continued with
        provenance :=
          .continued
            { original with completeCurrent := some 0, completeLag := some 0 }
            continuation }
     ] : List Candidate).all (fun c =>
      outcome (stateRequest c) == .selected 1 .conditionalImportedBase) = true := by decide
private def initialAt (h b applied : Nat) : Candidate :=
  let o : Original := { original with
    target := ⟨⟨h,hashC⟩,150⟩,
    base := ⟨b,hashE⟩,
    appliedLagBase := applied,
    headerPath := if b == 0 then [⟨b,hashE⟩,pin,⟨h,hashC⟩] else [pin,⟨b,hashE⟩,⟨h,hashC⟩],
    selected := false }
  { initial with tip := o.target, path := o.headerPath, provenance := .initial o }
example : appliedBaseHeight 15119 = none ∧
    appliedBaseHeight 15120 = some 0 ∧
    appliedBaseHeight 15839 = some 0 ∧
    appliedBaseHeight 15840 = some 720 := by decide
example :
    ([(15120,0,0), (15839,0,0), (15840,720,720)] : List (Nat × Nat × Nat)).all (fun x =>
      outcome (stateRequest (initialAt x.1 x.2.1 x.2.2)) ==
        .selected 1 .conditionalImportedBase) = true ∧
    ([(15119,0,0),
      (15840,15841,720), (15840,721,720),
      (15840,720,721)] : List (Nat × Nat × Nat)).all (fun x =>
      outcome (stateRequest (initialAt x.1 x.2.1 x.2.2)) == .missing [failure]) = true := by decide
example : outcome (stateRequest (initialAt 15840 15841 15841)) =
    .missing [failure] := by decide
example : outcome (stateRequest (initialAt 15840 721 721)) =
    .missing [failure] := by decide
example : outcome (stateRequest { initial with provenance := .initial { original with imageEntry := false } }) = .missing [failure] ∧
    outcome (stateRequest { initial with tip := ⟨initial.tip.point,151⟩ }) = .missing [failure] ∧
    outcome (stateRequest { initial with path := initial.path.reverse }) = .missing [failure] ∧
    outcome (stateRequest { high with provenance := .fullHistory false }) = .missing [failure] ∧
    outcome (stateRequest { continued with provenance := .continued { original with selected := false } continuation }) = .missing [failure] := by decide
example : outcome (stateRequest { continued with provenance := .continued original reconstructed, path := [pin,base,reconstructed.common.point,continued.tip.point] }) = .selected 1 .conditionalImportedBase ∧
    outcome (stateRequest { continued with tip := ⟨continued.tip.point,99⟩ }) = .missing [failure] := by decide
example : outcome (request (.states .entry) [continued,equalUnresolved 100] [equalFact]) = .unavailable ∧
    outcome (stateRequest { continued with tip := ⟨⟨722,hashD⟩,100⟩, path := [pin,base,⟨722,hashD⟩] }) = .selected 1 .conditionalImportedBase := by decide
example : ([ { original with completeCurrent := none }, { original with completeLag := none },
    { original with context := { ctx with network := 9 } }, { original with context := { ctx with genesis := 9 } },
    { original with context := { ctx with chainId := 9 } }, { original with context := { ctx with law := 9 } },
    { original with context := { ctx with history := 9 } }, { original with context := { ctx with release := 9 } },
    { original with imageEntry := false }, { original with imageCover := false },
    { original with historicalMembership := false }, { original with bothSeedCorrespondence := false },
    { original with rootIdentityMetadata := false }, { original with originalTailValidated := false },
    { original with originalPairComplete := false }, { original with appliedLagBase := 721 },
    { original with headersQualified := false } ] : List Original).all (fun o =>
      outcome (stateRequest { continued with provenance := .continued o continuation }) == .missing [failure]) = true := by decide
example : ([ { continuation with reconstructedPrefix := false }, { continuation with actualState := false },
    { continuation with undoSources := false }, { continuation with bodySources := false },
    { continuation with suffixSection25 := false } ] : List Continuation).all (fun k =>
      outcome (stateRequest { continued with provenance := .continued original k }) == .missing [failure]) = true ∧
    outcome (stateRequest { continued with provenance := .continued original { continuation with common := ⟨⟨719,hashD⟩,30⟩ }, path := [pin,⟨719,hashD⟩,base,continued.tip.point] }) = .missing [failure] ∧
    outcome (stateRequest { continued with provenance := .continued original reconstructed, path := [pin,reconstructed.common.point,continued.tip.point] }) = .missing [failure] ∧
    outcome (stateRequest { continued with path := [base,continued.tip.point] }) = .missing [failure] := by decide

-- F14/F15: T is not its heavier descendant; unknown state participates only in scheduling.
private def unknown : Candidate := { candidate 3 110 hashC .headerOnly with
  tip := ⟨⟨728,hashC⟩,110⟩, path := [pin,base,⟨726,hashA⟩,⟨728,hashC⟩] }
private def other : Candidate := candidate 2 105 hashB
private def headerPrefix : Candidate := { old with provenance := .headerOnly }
example : outcome { request .headers [unknown] with inventory := [headerPrefix,unknown], scanned := [headerPrefix,unknown], required := ⟨.notRequired,some headerPrefix,true,none,failure⟩ } =
      .scheduled 3 := by decide
example : outcome (request .headers [candidate 1 100,other,unknown] [unresolvedAt other]) = .scheduled 3 ∧
    outcome (request (.states .entry) [candidate 1 100,other,unknown] [unresolvedAt other]) = .unavailable ∧
    outcome (request (.states .entry) [candidate 1 100,{ other with provenance := .headerOnly },unknown]
      [unresolvedAt other]) = .selected 1 .fullHistory ∧
    outcome (request (.states .entry) [unknown]) = .selected 0 .fullHistory := by decide

-- F16/F17: fixed STEP owns local comparands; every global boundary keeps its inventory.
example : outcome (request (.fixedStep [1]) [high,other] [unresolvedAt other]) = .selected 1 .fullHistory ∧
    outcome { request (.fixedStep [1]) [high,other] with scanned := [old,{ high with pathComplete := false }], inventory := [old,{ high with pathComplete := false },other] } = .missing [failure] := by decide
example : ([Boundary.entry,.reentry,.preactivation,.outerSelection] : List Boundary).all (fun b =>
    outcome { request (.states b) [high,other] [unresolvedAt other] with scanned := [old,high] } ==
      .missing [inventoryFailure]) = true := by decide

-- F18/F19: alleged low rank cannot waive missing mandatory evidence or source owners.
example : ([ { low with actualWork := false }, { low with pathComplete := false },
    { low with headerRules := false }, { low with requiredSources := false },
    { low with context := { ctx with law := 9 } },
    { low with tip := ⟨⟨726,[1]⟩,100⟩, path := [pin,base,⟨726,[1]⟩] } ] : List Candidate).all (fun c =>
      outcome (request .headers [high,c] [unresolvedAt low]) == .missing [failure]) = true := by decide
-- A malformed tip and a separately malformed record each keep their source refusal.
example :
    let c := { low with tip := ⟨⟨726,[1]⟩,100⟩, path := [pin,base,⟨726,[1]⟩] }
    (match outcome (request .headers [high,c] [.rejection { uncertain with block := c.tip.point, refusal := inventoryFailure }]) with
     | .missing ds => ds.length == 2 && ds.contains inventoryFailure && ds.contains failure
     | _ => false) = true := by rfl
example : outcome { ordinary with membership := .unreadable failure } = .missing [failure] ∧
    outcome { ordinary with membership := .partialView failure } = .missing [failure] ∧
    outcome { ordinary with membership := .complete [.malformed failure] } = .missing [failure] ∧
    outcome { request (.states .entry) [high] with
      required := ⟨.required none,some old,true,some true,failure⟩ } = .missing [failure] ∧
    outcome { request (.states .entry) [high] with
      required := ⟨.required (some old),none,true,some true,failure⟩ } = .missing [failure] ∧
    outcome { ordinary with required := { ordinary.required with publishedPrefix := none } } = .missing [failure] ∧
    outcome { ordinary with required := { ordinary.required with sources := false } } = .missing [failure] ∧
    outcome { request (.states .entry) [high] with
      required := ⟨.required (some old),some old,true,some false,failure⟩ } = .missing [failure] := by decide

-- F20/F21: protected changes invalidate reuse; later failures cannot replace first truth.
example : ([ { basis with installation := 9 }, { basis with control := 9 },
    { basis with membershipVersion := 9 }, { basis with originalRevisions := [9] },
    { basis with correctiveRevisions := [9] }, { basis with sourceGuards := [9] },
    { basis with inventory := 9 }, { basis with path := 9 }, { basis with target := 8 },
    { basis with native := 9 }, { basis with comparands := 9 }, { basis with historicalScope := 9 } ] : List Basis).all (fun b =>
      outcome { ordinary with currentBasis := b } == .stale) = true ∧
    outcome { ordinary with basis := { basis with membershipVersion := 9 }, currentBasis := { basis with membershipVersion := 9 } } = .scheduled 1 := by decide
example : outcome { ordinary with firstObserved := some failure, membership := .unreadable inventoryFailure, currentBasis := { basis with native := 9 } } = .observed failure := by decide

-- F22/F23: no qualified W; all private/refused outcomes preserve public state and evidence.
example : outcome (request .headers [] [.rejection fact]) = .unavailable ∧
    outcome (request .headers [high] [.rejection fact]) = .unavailable ∧
    outcome (request .headers [high] [.rejection uncertain]) = .unavailable := by decide
example : (evaluate (stateRequest continued)).retained.publicState = ⟨42,[5],[],[]⟩ ∧
    (evaluate { stateRequest initial with firstObserved := some failure }).retained =
      { stateRequest initial with firstObserved := some failure } ∧
    outcome (stateRequest { continued with provenance := .continued original { continuation with suffixSection25 := false } }) =
      .missing [failure] := by decide

end RubinFormal.JournalChoice
