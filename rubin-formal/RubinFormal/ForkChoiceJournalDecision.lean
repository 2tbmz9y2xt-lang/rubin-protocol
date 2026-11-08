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

/-- The scope owner qualifies SAME/DIFFERENT on the exact consumer basis and
    full provenance; the projected Context does not derive that relation. -/
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
  /-- Positive external evidence for scope on the exact consumer basis. -/
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
    relation ctx high.path { fact with scope := .different } = .eligible ∧
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
    relation ctx disputed.path { differentFact with origin := .fullHistory own true, scopeQualified := false } == .unresolved &&
    outcome (request .headers [lowerIndependent,disputed]
      [.rejection { differentFact with origin := .fullHistory own true, scopeQualified := false }]) == .unavailable) = true := by decide
example : ([ctx,{ ctx with release := 60 },{ ctx with law := 40 },{ ctx with history := 50 }] : List Context).all (fun own =>
    relation ctx disputed.path { differentFact with origin := .fullHistory own true } == .eligible &&
    outcome (request .headers [lowerIndependent,disputed]
      [.rejection { differentFact with origin := .fullHistory own true }]) == .scheduled 2) = true := by decide
example : relation ctx tailDisputed.path { reachedFact with scope := .different } = .eligible ∧
    outcome (request .headers [lowerIndependent,tailDisputed]
      [.rejection { reachedFact with scope := .different }]) = .scheduled 2 := by decide

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

/-!
RUB-1795 R1–R7: bounded model of the selected proposed recovery-only rule.
Canonical premises are rubin-spec@c5e701492940c407a9267be9e194f98e54241149,
CANONICAL §§5/8/10/23/25 and MEMPOOL §§6.4.1.4/6.4.1.8/6.4.1.9.
Parse, header/hash authentication, historical meaning, complete source census
and actual P/native readback are supplied observations. No bytes, codec, DB,
physical crash, client correspondence or ordinary public error is proved here.
The ordinary JournalChoice namespace above remains supplementary/unregistered.
-/
namespace RubinFormal.RecoveryCore

open JournalChoice (Tip Context Refusal Scope Health Assurance strictlyOutranks)

structure Key where
  height : Nat
  hash : List UInt8
  parent : List UInt8
deriving BEq, DecidableEq, Repr

inductive OutputType where
  | coreAnchor
  | other
deriving BEq, DecidableEq, Repr

structure Output where
  covenantType : OutputType
  dataLength : Nat
  value : Nat
  payload : Nat
deriving BEq, DecidableEq, Repr

structure Core where
  kind : Nat
  payloadLength : Nat
  outputs : List Output
  witnessNonempty : Bool
  manifestNonempty : Bool
  commitmentWrong : Bool
deriving BEq, DecidableEq, Repr

/-- The final three flags are copy observations, not authenticated core fields. -/
def sameCommittedCore (a b : Core) : Bool :=
  a.kind == b.kind && a.payloadLength == b.payloadLength && a.outputs == b.outputs

inductive Reason where
  | anchorCount
  | positionZeroChunk
deriving BEq, DecidableEq, Repr

def anchorCount (c : Core) : Nat :=
  (c.outputs.filter (fun o => o.covenantType == .coreAnchor && o.dataLength == 32)).length

/-- Count precedes kind. Value, commitment bytes and copy-only fields do not count. -/
def structuralReason (c : Core) : Option Reason :=
  if anchorCount c != 1 then some .anchorCount
  else if c.kind == 2 then some .positionZeroChunk else none

inductive Acquisition where
  | genesisReplay
  | archivePrefix
  | imageTail
  | direct
  | staging
  | entry
  | prunedPrefix
deriving BEq, DecidableEq, Repr

structure Probe where
  acquisition : Acquisition
  reached : Bool
  uncommitted : Bool
  phaseAuthority : Bool
  reserved : Bool
  source : Bool
  stores : Bool
  canonicalParse : Bool
  nonzeroTransactions : Bool
  noTrailingBytes : Bool
  legalKindPayload : Bool
  expectedHeader : Bool
  expectedHeight : Bool
  expectedParentPath : Bool
  chainGenesis : Bool
  historicalContext : Bool
  headerGates : Bool
  orderedRoot : Bool
  firstObserved : Option Refusal
  core : Core
deriving BEq, DecidableEq, Repr

def acquisitionOwnsProof : Acquisition → Bool
  | .genesisReplay | .archivePrefix | .imageTail => true
  | .direct | .staging | .entry | .prunedPrefix => false

def probeQualified (p : Probe) : Bool :=
  acquisitionOwnsProof p.acquisition && p.reached && p.uncommitted &&
  p.phaseAuthority && p.reserved && p.source && p.stores && p.canonicalParse &&
  p.nonzeroTransactions && p.noTrailingBytes && p.legalKindPayload &&
  p.core.kind <= 2 && (p.core.kind != 2 || p.core.payloadLength > 0) &&
  p.expectedHeader && p.expectedHeight && p.expectedParentPath && p.chainGenesis &&
  p.historicalContext && p.headerGates && p.orderedRoot

structure ProbeResult where
  reason : Option Reason
  firstObserved : Option Refusal
deriving BEq, DecidableEq, Repr

def probe (p : Probe) : ProbeResult :=
  match p.firstObserved with
  | some first => ⟨none, some first⟩
  | none => ⟨if probeQualified p then structuralReason p.core else none, none⟩

inductive Backing where
  | retained (owner : Nat)
  | generation (owner : Nat)
  | digestOnly
  | ephemeral
deriving BEq, DecidableEq, Repr

structure Source where
  identity : Nat
  backing : Backing
  bytes : Nat
  manifestBytes : Nat
  completeBytes : Bool
  reproductionInputs : Bool
  immutable : Bool
  identityQualified : Bool
deriving BEq, DecidableEq, Repr

def independentSource (s : Source) (retiring : List Nat) : Bool :=
  s.completeBytes && s.reproductionInputs && s.immutable && s.identityQualified &&
  s.bytes > 0 && match s.backing with
    | .retained owner => !(retiring.contains owner)
    | .generation _ | .digestOnly | .ephemeral => false

structure Identity where
  installation : Nat
  context : Context
  ruleVersion : Nat
  bindingVersion : Nat
  b0 : Nat
  h0 : Nat
  e0 : Nat
  complete : Nat
  assurance : Assurance
deriving BEq, DecidableEq, Repr

/-- Logical immutable payload; no rejection, correction, terminal or credit field. -/
structure Payload where
  identity : Identity
  block : Key
  core : Core
  count : Nat
  reason : Reason
  source : Source
  acquisition : Acquisition
  position : Nat
deriving BEq, DecidableEq, Repr

/-- Current external qualification observations, distinct from the stored payload. -/
structure ProofView where
  payload : Payload
  scope : Scope
  scopeQualified : Bool
  originalQualified : Bool
  sourceAvailable : Bool
  health : Health
  conflictingCore : Bool
  sameLawAcceptance : Bool
deriving BEq, DecidableEq, Repr

inductive Record where
  | recoveryCoreImpossible (view : ProofView)
  | nonoperative
  | malformed
deriving BEq, DecidableEq, Repr

inductive Membership where
  | complete (records : List Record)
  | partialView
  | unreadable
deriving BEq, DecidableEq, Repr

def payloadValid (p : Payload) : Bool :=
  p.block.hash.length == 32 && p.block.parent.length == 32 &&
  p.core.kind <= 2 && (p.core.kind != 2 || p.core.payloadLength > 0) &&
  p.count == anchorCount p.core && structuralReason p.core == some p.reason &&
  acquisitionOwnsProof p.acquisition

def membershipReady : Membership → Bool
  | .complete rows => rows.all fun r => match r with
      | .recoveryCoreImpossible v => payloadValid v.payload
      | .nonoperative => true
      | .malformed => false
  | .partialView | .unreadable => false

inductive Relation where
  | eligible
  | excluded
  | unresolved
deriving BEq, DecidableEq, Repr

def proofRelation (ctx : Context) (installation : Nat) (path : List Key)
    (v : ProofView) : Relation :=
  if !(path.any (fun b => b.hash == v.payload.block.hash)) then .eligible
  else if !(path.contains v.payload.block) then .unresolved
  else if !v.scopeQualified || !v.originalQualified || !v.sourceAvailable ||
      v.health != .qualified || v.conflictingCore || v.sameLawAcceptance ||
      v.payload.identity.installation != installation ||
      v.payload.identity.context.network != ctx.network ||
      v.payload.identity.context.genesis != ctx.genesis ||
      v.payload.identity.context.chainId != ctx.chainId ||
      !(independentSource v.payload.source []) then .unresolved
  else match v.scope with
    | .same => .excluded
    | .different => .eligible
    | .unresolved => .unresolved

def views : Membership → List ProofView
  | .complete rows => rows.filterMap fun r => match r with
      | .recoveryCoreImpossible v => some v
      | _ => none
  | _ => []

def relation (m : Membership) (ctx : Context) (installation : Nat)
    (currentBasis pathComplete : Bool) (path : List Key) : Relation :=
  if !membershipReady m || !currentBasis || !pathComplete then .unresolved
  else
    let vs := views m
    let rs := vs.map fun v =>
      if path.any (fun b => b.hash == v.payload.block.hash) && vs.any (fun w =>
          w.payload.block.hash == v.payload.block.hash &&
          (w.payload.block != v.payload.block ||
            (w.payload.identity == v.payload.identity &&
              !sameCommittedCore w.payload.core v.payload.core)))
      then .unresolved else proofRelation ctx installation path v
    if rs.contains .excluded then .excluded
    else if rs.contains .unresolved then .unresolved else .eligible

structure Observations where
  invalidBranches : List Nat
  exactRejections : List Nat
  canonical : Nat
  relay : List Nat
  alarms : List Nat
  h1Events : List Nat
  actualTerminal : Option Nat
  actualError : Option Nat
deriving BEq, DecidableEq, Repr

structure Candidate where
  id : Nat
  tip : Tip
  path : List Key
  pathComplete : Bool
  headers : Bool
  actualWork : Bool
  sources : Bool
  eligibleState : Bool
  assurance : Assurance
deriving BEq, DecidableEq, Repr

structure SelectionRequest where
  context : Context
  installation : Nat
  currentBasis : Bool
  inventoryComplete : Bool
  oldComplete : Bool
  oldEligible : Bool
  oldTip : Tip
  requiredSources : Bool
  candidates : List Candidate
  membership : Membership
  profile : Nat
  source : Nat
  intent : Nat
  allocations : Nat
  prebaseFetches : Nat
  observations : Observations
  firstObserved : Option Refusal
deriving BEq, DecidableEq, Repr

inductive Choice where
  | winner (id : Nat) (assurance : Assurance)
  | pending
  | refused
  | observed (first : Refusal)
deriving BEq, DecidableEq, Repr

def candidateReady (c : Candidate) : Bool :=
  c.pathComplete && c.headers && c.actualWork && c.sources &&
  c.tip.point.hash.length == 32 && c.path.all (fun b =>
    b.hash.length == 32 && b.parent.length == 32) &&
  c.path.any (fun b => b.height == c.tip.point.height && b.hash == c.tip.point.hash)

/-- Actual-state comparison projection; header-only scheduling is outside this model. -/
def select (r : SelectionRequest) : Choice :=
  match r.firstObserved with
  | some first => .observed first
  | none =>
    if !r.currentBasis || !r.inventoryComplete || !r.oldComplete || !r.oldEligible ||
        !r.requiredSources || !membershipReady r.membership ||
        !(r.candidates.all candidateReady) then .refused
    else
      let rel := fun (c : Candidate) => relation r.membership r.context r.installation
        r.currentBasis c.pathComplete c.path
      let stateDomain := r.candidates.filter (fun c => c.eligibleState && c.tip.point.height > 0)
      let eligible := stateDomain.filter (fun c => rel c == .eligible)
      match eligible with
      | [] => .pending
      | first :: rest =>
        let winner := rest.foldl (fun w c => if strictlyOutranks c.tip w.tip then c else w) first
        if !strictlyOutranks winner.tip r.oldTip ||
            !(stateDomain.all (fun u => rel u != .unresolved ||
              strictlyOutranks winner.tip u.tip)) ||
            eligible.any (fun c => c.id != winner.id && c.tip == winner.tip)
        then .pending else .winner winner.id winner.assurance

structure SelectionResult where
  choice : Choice
  retained : SelectionRequest
deriving BEq, DecidableEq, Repr

def evaluateSelection (r : SelectionRequest) : SelectionResult := ⟨select r, r⟩

inductive Truth where
  | old
  | new
  | unknown
deriving BEq, DecidableEq, Repr

structure Journal where
  membership : Membership
  slots : Nat
  contexts : Nat
  contextIds : List Nat
  bytes : Nat
  sourceCensus : List Source
  sequence : Nat
  revision : Nat
  heldSource : Option Source
  observations : Observations
deriving BEq, DecidableEq, Repr

structure CaptureRequest where
  probeInput : Probe
  identity : Identity
  block : Key
  position : Nat
  source : Source
  retiring : List Nat
  contextId : Nat
  contextBytes : Nat
  recordBytes : Nat
  controlBytes : Nat
  operationHeldBytes : Nat
  byteCap : Nat
  operation : Nat
  reservationOwner : Option Nat
  exclusiveWriter : Bool
  currentBasis : Bool
  sourceHealthy : Bool
  contradiction : Bool
  pTruth : Truth
  peer : Nat
  requestLabel : Nat
  generationLabel : Nat
deriving BEq, DecidableEq, Repr

def capturePayload (r : CaptureRequest) (why : Reason) : Payload :=
  ⟨r.identity, r.block, r.probeInput.core, anchorCount r.probeInput.core, why,
    r.source, r.probeInput.acquisition, r.position⟩

/-- Provenance labels are not fact identity; original binding/source are. -/
def sameFact (a b : Payload) : Bool :=
  a.identity == b.identity && a.block == b.block && sameCommittedCore a.core b.core &&
  a.count == b.count && a.reason == b.reason && a.source == b.source

def captureCharge (j : Journal) (r : CaptureRequest) : Nat :=
  r.recordBytes + r.controlBytes + r.operationHeldBytes +
  (if j.contextIds.contains r.contextId then 0 else r.contextBytes) +
  (if j.sourceCensus.contains r.source then 0 else r.source.bytes + r.source.manifestBytes)

inductive CaptureStatus where
  | noProof
  | refused
  | duplicate
  | old
  | new
  | unknown
deriving BEq, DecidableEq, Repr

structure CaptureResult where
  status : CaptureStatus
  journal : Journal
deriving BEq, DecidableEq, Repr

def capture (j : Journal) (r : CaptureRequest) : CaptureResult :=
  match (probe r.probeInput).reason with
  | none => ⟨.noProof, j⟩
  | some why =>
    let payload := capturePayload r why
    if !membershipReady j.membership || !payloadValid payload || !r.currentBasis ||
        !r.exclusiveWriter || r.reservationOwner != some r.operation ||
        !r.sourceHealthy || r.contradiction || j.heldSource != some r.source ||
        !independentSource r.source r.retiring ||
        j.sourceCensus.any (fun s => s.identity == r.source.identity && s != r.source)
    then ⟨.refused, j⟩
    else if (views j.membership).any (fun v => sameFact v.payload payload) then ⟨.duplicate, j⟩
    else if j.slots >= 65536 ||
        j.contexts + (if j.contextIds.contains r.contextId then 0 else 1) > 1024 ||
        j.bytes + captureCharge j r > r.byteCap ||
        j.sequence >= 18446744073709551615 || j.revision >= 18446744073709551615
    then ⟨.refused, j⟩
    else match r.pTruth with
      | .old => ⟨.old, j⟩
      | .unknown => ⟨.unknown, j⟩
      | .new =>
        let row : ProofView := ⟨payload, .same, true, true, true, .qualified, false, false⟩
        let rows := match j.membership with | .complete rs => rs | _ => []
        ⟨.new, { j with
          membership := .complete (rows ++ [.recoveryCoreImpossible row])
          slots := j.slots + 1
          contexts := j.contexts + (if j.contextIds.contains r.contextId then 0 else 1)
          contextIds := if j.contextIds.contains r.contextId then j.contextIds else j.contextIds ++ [r.contextId]
          bytes := j.bytes + captureCharge j r
          sourceCensus := if j.sourceCensus.contains r.source then j.sourceCensus else j.sourceCensus ++ [r.source]
          sequence := j.sequence + 1
          revision := j.revision + 1 }⟩

inductive Phase where
  | replay
  | cleanup
  | pending
deriving BEq, DecidableEq, Repr

/-- H1 diagnostic/forensic/control state is not the actual native R path. -/
structure Control where
  d : Nat
  t0 : Nat
  diagnosticPath : List Key
  a0 : Nat
  quarantinedOld : List Nat
  installation : Nat
  networkControl : Nat
  consumedIntent : Nat
  originalResult : Nat
  attempts : Nat
  credits : Nat
deriving BEq, DecidableEq, Repr

structure Native where
  phase : Phase
  actualR : Option Nat
  path : List Key
  pathComplete : Bool
  replay : Bool
  cursor : Option Nat
  q : Option Nat
  maps : List Nat
  both : List Nat
  targetGenerations : List Nat
  cleanup : List Nat
  drained : List Nat
  conversions : Nat
  allocations : Nat
  publicOld : Nat
  profile : Nat
  intent : Nat
  sourceOwner : Nat
  control : Control
  observations : Observations
  skippedExecutions : Nat
  prebaseFetches : Nat
deriving BEq, DecidableEq, Repr

structure NativeGuards where
  context : Context
  installation : Nat
  currentBasis : Bool
  roles : Bool
  sourceCursor : Bool
  pTruth : Truth
  nativeTruth : Truth
deriving BEq, DecidableEq, Repr

def ascendingBoth : List Nat → Option (List Nat)
  | [a,b] => if a == b then none else if a < b then some [a,b] else some [b,a]
  | _ => none

inductive Effect where
  | unchanged
  | blocked
  | old
  | unknown
  | converted
  | drained (generation : Nat)
  | pending
deriving BEq, DecidableEq, Repr

structure NativeResult where
  effect : Effect
  state : Native
deriving BEq, DecidableEq, Repr

/-- Fixed STEP uses actual R only and performs no global candidate inventory. -/
def nativeStep (m : Membership) (g : NativeGuards) (n : Native) : NativeResult :=
  if !g.currentBasis || !g.roles || !g.sourceCursor || !membershipReady m ||
      !n.pathComplete then ⟨.blocked, n⟩
  else if g.pTruth == .unknown then ⟨.unknown, n⟩
  else if g.pTruth != .new then ⟨.old, n⟩
  else if g.nativeTruth == .unknown then ⟨.unknown, n⟩
  else if g.nativeTruth != .new then ⟨.old, n⟩
  else
    let rel := relation m g.context g.installation g.currentBasis n.pathComplete n.path
    let retained := (views m).all fun v =>
      proofRelation g.context g.installation n.path v != .excluded ||
      independentSource v.payload.source n.targetGenerations
    if rel == .unresolved || !retained then ⟨.blocked, n⟩
    else match n.phase with
      | .pending => ⟨.pending, n⟩
      | .replay =>
        if rel != .excluded then ⟨.unchanged, n⟩
        else match ascendingBoth n.both with
          | none => ⟨.blocked, n⟩
          | some generations =>
            if !n.replay || n.actualR == none || n.both != n.targetGenerations ||
                !n.cleanup.isEmpty || !n.drained.isEmpty then ⟨.blocked, n⟩
            else ⟨.converted, { n with
              phase := .cleanup, replay := false,
              cursor := none, q := none, maps := [], both := [], cleanup := generations,
              conversions := n.conversions + 1 }⟩
      | .cleanup =>
        match n.cleanup with
        | [] => ⟨.pending, { n with phase := .pending, actualR := none, path := [] }⟩
        | generation :: rest =>
          if n.replay || n.cursor != none || n.q != none || !n.maps.isEmpty ||
              !n.both.isEmpty || n.drained.contains generation then ⟨.blocked, n⟩
          else ⟨.drained generation, { n with cleanup := rest, drained := n.drained ++ [generation] }⟩

-- Fixed expectations below use the computed owners, never supplied exclusion,
-- conversion or expected-value helpers. Hashes label assumed authenticated data.
private def h (n : UInt8) : List UInt8 := List.replicate 31 0 ++ [n]
private def ctx : Context := ⟨1,2,3,4,5,6⟩
private def parent : Key := ⟨9,h 1,h 0⟩
private def b : Key := ⟨10,h 2,h 1⟩
private def descendant : Key := ⟨11,h 3,h 2⟩
private def sibling : Key := ⟨10,h 4,h 1⟩
private def another : Key := ⟨10,h 5,h 1⟩
private def anchor : Output := ⟨.coreAnchor,32,0,77⟩
private def chunk : Core := ⟨2,1,[anchor],false,false,false⟩
private def ordinary : Core := { chunk with kind := 0, payloadLength := 0 }
private def first : Refusal := ⟨71,"SOURCE_OBSERVATION","first reached owner",3,4,5⟩
private def acquired : Probe :=
  ⟨.genesisReplay,true,true,true,true,true,true,true,true,true,true,true,true,
    true,true,true,true,true,none,chunk⟩
private def source : Source := ⟨77,.retained 99,64,4,true,true,true,true⟩
private def identity : Identity := ⟨8,ctx,11,12,9,15,16,17,.conditionalImportedBase⟩
private def fact : ProofView :=
  ⟨⟨identity,b,chunk,1,.positionZeroChunk,source,.genesisReplay,10⟩,
    .same,true,true,true,.qualified,false,false⟩
private def member : Membership := .complete [.recoveryCoreImpossible fact]
private def observed : Observations := ⟨[21],[22],23,[24],[25],[26],some 27,some 28⟩
private def emptyObserved : Observations := ⟨[],[],0,[],[],[],none,none⟩

-- F01: each false gate is otherwise admitted and cannot produce a proof.
def predicateCases : Bool :=
  probe acquired == ⟨some .positionZeroChunk,none⟩ &&
  ([Acquisition.genesisReplay,.archivePrefix,.imageTail] : List Acquisition).all
    (fun mode => (probe { acquired with acquisition := mode }).reason == some .positionZeroChunk) &&
  ([Acquisition.direct,.staging,.entry,.prunedPrefix] : List Acquisition).all
    (fun mode => (probe { acquired with acquisition := mode }).reason == none) &&
  (probe { acquired with core := { ordinary with outputs := [] } }).reason == some .anchorCount &&
  (probe { acquired with core := { ordinary with outputs := [anchor,anchor] } }).reason == some .anchorCount &&
  (probe { acquired with core := { chunk with outputs := [anchor,anchor] } }).reason == some .anchorCount &&
  (probe { acquired with core := { chunk with outputs := [{ anchor with value := 99, payload := 0 }] } }).reason == some .positionZeroChunk &&
  (probe { acquired with core := { chunk with outputs := [anchor,⟨.other,32,7,77⟩] } }).reason == some .positionZeroChunk &&
  ([31,33] : List Nat).all (fun len =>
    (probe { acquired with core := { chunk with outputs := [{ anchor with dataLength := len }] } }).reason == some .anchorCount) &&
  (probe { acquired with core := { chunk with outputs := [⟨.other,32,0,77⟩] } }).reason == some .anchorCount &&
  ([ordinary,{ ordinary with witnessNonempty := true },
    { ordinary with manifestNonempty := true },{ ordinary with commitmentWrong := true },
    { ordinary with kind := 1, payloadLength := 1, manifestNonempty := true }] : List Core).all
    (fun c => (probe { acquired with core := c }).reason == none) &&
  ([{ acquired with reached := false },{ acquired with uncommitted := false },
    { acquired with phaseAuthority := false },{ acquired with reserved := false },
    { acquired with source := false },{ acquired with stores := false },
    { acquired with canonicalParse := false },{ acquired with nonzeroTransactions := false },
    { acquired with noTrailingBytes := false },{ acquired with legalKindPayload := false },
    { acquired with expectedHeader := false },{ acquired with expectedHeight := false },
    { acquired with expectedParentPath := false },{ acquired with chainGenesis := false },
    { acquired with historicalContext := false },{ acquired with headerGates := false },
    { acquired with orderedRoot := false },
    { acquired with core := { chunk with kind := 3 } },
    { acquired with core := { chunk with payloadLength := 0 } }] : List Probe).all
    (fun p => (probe p).reason == none) &&
  probe { acquired with firstObserved := some first, stores := false } == ⟨none,some first⟩

private def rel (m : Membership) (path : List Key := [parent,b,descendant]) : Relation :=
  relation m ctx 8 true true path
private def row (v : ProofView) : Membership := .complete [.recoveryCoreImpossible v]
private def conflictingB : Membership := .complete [.recoveryCoreImpossible fact,
  .recoveryCoreImpossible { fact with payload := { fact.payload with block := { b with parent := h 9 } } }]
-- C has a distinct original context/source, positively SAME law, outside B's affected context.
private def conflictingBWithC : Membership := .complete [.recoveryCoreImpossible fact,
  .recoveryCoreImpossible { fact with payload := { fact.payload with block := { b with parent := h 9 } } },
  .recoveryCoreImpossible { fact with payload := { fact.payload with
    block := descendant,
    identity := { identity with context := { ctx with release := 7 } },
    position := 11, source := { source with identity := 78, backing := .retained 100 } } }]

-- F02: raw absence precedes row-only dependencies; tuple mismatch is not absence.
def qualificationCases : Bool :=
  rel member == .excluded &&
  rel member [parent,sibling] == .eligible && rel member [parent] == .eligible &&
  rel (row { fact with
    scope := .unresolved, sourceAvailable := false,
    originalQualified := false, scopeQualified := false }) [parent,sibling] == .eligible &&
  rel member [parent,{ b with height := 12 }] == .unresolved &&
  rel member [parent,{ b with parent := h 9 }] == .unresolved &&
  rel (row { fact with scope := .different }) == .eligible &&
  ([{ fact with scope := .unresolved },{ fact with scopeQualified := false },
    { fact with originalQualified := false },{ fact with sourceAvailable := false },
    { fact with health := .suspect },{ fact with health := .unresolved },
    { fact with conflictingCore := true },{ fact with sameLawAcceptance := true },
    { fact with payload := { fact.payload with source := { source with identityQualified := false } } },
    { fact with payload := { fact.payload with identity := { identity with installation := 9 } } },
    { fact with payload := { fact.payload with identity := { identity with context := { ctx with network := 9 } } } },
    { fact with payload := { fact.payload with identity := { identity with context := { ctx with genesis := 9 } } } },
    { fact with payload := { fact.payload with identity := { identity with context := { ctx with chainId := 9 } } } }] : List ProofView).all
    (fun v => rel (row v) == .unresolved) &&
  ([{ fact with scope := .different, originalQualified := false },
    { fact with scope := .different, sourceAvailable := false },
    { fact with scope := .different, scopeQualified := false }] : List ProofView).all
    (fun v => rel (row v) == .unresolved) &&
  ([Membership.partialView,.unreadable,.complete [.malformed],
    row { fact with payload := { fact.payload with count := 2 } },
    row { fact with payload := { fact.payload with reason := .anchorCount } }] : List Membership).all
    (fun m => rel m [parent,sibling] == .unresolved) &&
  relation member ctx 8 false true [parent,b] == .unresolved &&
  relation member ctx 8 true false [parent,sibling] == .unresolved &&
  rel conflictingB == .unresolved &&
  rel conflictingBWithC == .excluded &&
  rel (.complete [.recoveryCoreImpossible fact,.recoveryCoreImpossible
    { fact with payload := { fact.payload with core := { chunk with outputs := [{ anchor with payload := 88 }] } } }]) == .unresolved
  && ([{ chunk with witnessNonempty := true },{ chunk with manifestNonempty := true },
    { chunk with commitmentWrong := true }] : List Core).all (fun c =>
      rel (.complete [.recoveryCoreImpossible fact,.recoveryCoreImpossible
        { fact with payload := { fact.payload with core := c } }]) == .excluded)

private def candidate (id work : Nat) (tip : Key) (path : List Key) : Candidate :=
  ⟨id,⟨⟨tip.height,tip.hash⟩,work⟩,path,true,true,true,true,true,.conditionalImportedBase⟩
private def blocked : Candidate := candidate 1 100 descendant [parent,b,descendant]
private def w : Candidate := candidate 2 90 sibling [parent,sibling]
private def low : Candidate := candidate 3 80 another [parent,another]
private def selection : SelectionRequest :=
  ⟨ctx,8,true,true,true,true,⟨⟨9,h 1⟩,70⟩,true,[blocked,w,low],member,
    31,32,33,0,0,observed,none⟩
private def u : Candidate := { blocked with tip := ⟨blocked.tip.point,80⟩ }
private def uncertainMember : Membership := row { fact with sourceAvailable := false }
private def nonStateU : Candidate := { blocked with eligibleState := false }

-- F03: complete filtering precedes rank; only journal uncertainty admits W/U independence.
def selectionCases : Bool :=
  select selection == .winner 2 .conditionalImportedBase &&
  select { selection with candidates := selection.candidates.reverse } == .winner 2 .conditionalImportedBase &&
  select { selection with candidates := [candidate 4 100 b [parent,b],w] } == .winner 2 .conditionalImportedBase &&
  select { selection with candidates := [candidate 4 95 parent [parent]] } == .winner 4 .conditionalImportedBase &&
  select { selection with membership := conflictingB, candidates := [blocked,w] } == .pending &&
  select { selection with membership := conflictingBWithC, candidates := [blocked,w] } == .winner 2 .conditionalImportedBase &&
  select { selection with membership := .complete [], candidates := [w,nonStateU] } == .winner 2 .conditionalImportedBase &&
  select { selection with membership := uncertainMember, candidates := [w,nonStateU] } == .winner 2 .conditionalImportedBase &&
  select { selection with membership := uncertainMember, candidates := [w,blocked] } == .pending &&
  select { selection with membership := uncertainMember, candidates := [w,u] } == .winner 2 .conditionalImportedBase &&
  select { selection with membership := uncertainMember, candidates := [u,w] } == .winner 2 .conditionalImportedBase &&
  select { selection with
    membership := uncertainMember,
    candidates := [w,{ u with tip := ⟨u.tip.point,91⟩ }] } == .pending &&
  select { selection with
    membership := uncertainMember,
    candidates := [{ w with tip := ⟨w.tip.point,80⟩ },u] } == .pending &&
  select { selection with
    membership := uncertainMember,
    candidates := [{ w with
      tip := ⟨⟨sibling.height,h 1⟩,80⟩,
      path := [parent,{ sibling with hash := h 1 }] },u] } == .winner 2 .conditionalImportedBase &&
  select { selection with
    membership := uncertainMember,
    candidates := [{ w with tip := u.tip, path := [parent,{ sibling with hash := h 3, height := 11 }] },u] } == .pending &&
  ([{ selection with currentBasis := false },{ selection with inventoryComplete := false },
    { selection with oldComplete := false },{ selection with oldEligible := false },
    { selection with requiredSources := false },{ selection with membership := .unreadable }] : List SelectionRequest).all
    (fun r => select r == .refused) &&
  ([{ u with pathComplete := false },{ u with headers := false },
    { u with actualWork := false },{ u with sources := false },
    { nonStateU with pathComplete := false },{ nonStateU with headers := false },
    { nonStateU with actualWork := false },{ nonStateU with sources := false }] : List Candidate).all
    (fun c => select { selection with membership := uncertainMember, candidates := [w,c] } == .refused) &&
  ([[],[blocked],[{ w with eligibleState := false }],
    [candidate 4 200 ⟨0,h 9,h 0⟩ [⟨0,h 9,h 0⟩]],
    [{ w with tip := ⟨w.tip.point,60⟩ }]] : List (List Candidate)).all
    (fun cs => select { selection with candidates := cs } == .pending) &&
  (evaluateSelection { selection with candidates := [blocked] }).retained ==
    { selection with candidates := [blocked] } &&
  (evaluateSelection selection).retained.observations == observed &&
  select { selection with firstObserved := some first, inventoryComplete := false } == .observed first

private def journal : Journal := ⟨.complete [],65535,1023,[],900,[],10,20,some source,observed⟩
private def captureRequest : CaptureRequest :=
  ⟨acquired,identity,b,10,source,[12,11],42,8,16,4,4,1000,7,some 7,
    true,true,true,false,.new,1,2,3⟩
private def captured : Journal := (capture journal captureRequest).journal
private def captureImage (r : CaptureResult) :
    CaptureStatus × Nat × Nat × Nat × Nat × Nat × List Nat × List Source × Option Source :=
  (r.status,r.journal.slots,r.journal.contexts,r.journal.bytes,r.journal.sequence,
    r.journal.revision,r.journal.contextIds,r.journal.sourceCensus,r.journal.heldSource)

-- F04: aggregate counters abstract unrelated rows; source/metadata/held-byte union is charged here.
def captureCases : Bool :=
  captureImage (capture journal captureRequest) ==
    (.new,65536,1024,1000,11,21,[42],[source],some source) &&
  membershipReady captured.membership &&
  (views captured.membership).map (fun v =>
    (v.payload.count,v.payload.reason,v.payload.source.identity,v.payload.identity)) ==
      [(1,.positionZeroChunk,77,identity)] &&
  capture captured { captureRequest with peer := 90, requestLabel := 91, generationLabel := 92 } ==
    ⟨.duplicate,captured⟩ &&
  ([{ chunk with witnessNonempty := true },{ chunk with manifestNonempty := true },
    { chunk with commitmentWrong := true }] : List Core).all (fun c =>
      capture captured { captureRequest with probeInput := { acquired with core := c } } ==
        ⟨.duplicate,captured⟩) &&
  capture journal { captureRequest with pTruth := .old } == ⟨.old,journal⟩ &&
  capture journal { captureRequest with pTruth := .unknown } == ⟨.unknown,journal⟩ &&
  ([{ journal with slots := 65536 },{ journal with contexts := 1024 },
    { journal with bytes := 901 },{ journal with sequence := 18446744073709551615 },
    { journal with revision := 18446744073709551615 },
    { journal with heldSource := none },
    { journal with heldSource := some { source with identity := 78 } },
    { journal with membership := .partialView },{ journal with membership := .unreadable },
    { journal with membership := .complete [.malformed] },
    { journal with sourceCensus := [{ source with bytes := 65 }] }] : List Journal).all
    (fun j => capture j captureRequest == ⟨.refused,j⟩) &&
  ([{ captureRequest with reservationOwner := some 8 },{ captureRequest with reservationOwner := none },
    { captureRequest with exclusiveWriter := false },{ captureRequest with currentBasis := false },
    { captureRequest with sourceHealthy := false },{ captureRequest with contradiction := true },
    { captureRequest with source := { source with backing := .retained 11 } },
    { captureRequest with source := { source with backing := .generation 11 } },
    { captureRequest with source := { source with backing := .digestOnly } },
    { captureRequest with source := { source with backing := .ephemeral } },
    { captureRequest with source := { source with completeBytes := false } },
    { captureRequest with source := { source with reproductionInputs := false } },
    { captureRequest with source := { source with immutable := false } },
    { captureRequest with source := { source with identityQualified := false } },
    { captureRequest with source := { source with bytes := 0 } }] : List CaptureRequest).all
    (fun r =>
      let j := { journal with heldSource := some r.source }
      capture j r == ⟨.refused,j⟩) &&
  capture journal { captureRequest with probeInput := { acquired with firstObserved := some first } } ==
    ⟨.noProof,journal⟩ &&
  captureImage (capture { journal with contexts := 1024, contextIds := [42], bytes := 908 }
    captureRequest) == (.new,65536,1024,1000,11,21,[42],[source],some source) &&
  captureImage (capture { journal with sourceCensus := [source], bytes := 968 }
    captureRequest) == (.new,65536,1024,1000,11,21,[42],[source],some source) &&
  (capture journal captureRequest).journal.observations == observed

private def control : Control := ⟨51,52,[parent,sibling],53,[54,55],8,56,57,58,59,60⟩
private def native : Native :=
  ⟨.replay,some 61,[parent,b,descendant],true,true,some 10,some 10,[62,63],
    [12,11],[12,11],[],[],0,1,64,31,33,32,control,observed,0,0⟩
private def guards : NativeGuards := ⟨ctx,8,true,true,true,.new,.new⟩
private def converted : Native := (nativeStep captured.membership guards native).state
private def drainedFirst : Native := (nativeStep captured.membership guards converted).state
private def drainedSecond : Native := (nativeStep captured.membership guards drainedFirst).state
private def pending : Native := (nativeStep captured.membership guards drainedSecond).state
private def replayImage (n : Native) :
    Phase × Bool × Option Nat × Option Nat × List Nat × List Nat × List Nat × List Nat × Nat :=
  (n.phase,n.replay,n.cursor,n.q,n.maps,n.both,n.cleanup,n.drained,n.conversions)
private def retainedImage (n : Native) : Nat × Nat × Nat × Nat × Nat × Control × Observations × Nat × Nat :=
  (n.allocations,n.publicOld,n.profile,n.intent,n.sourceOwner,n.control,n.observations,
    n.skippedExecutions,n.prebaseFetches)

-- F05: P and native readbacks are independent; restart resumes the actual phase.
def dispositionCases : Bool :=
  nativeStep captured.membership { guards with nativeTruth := .old } native == ⟨.old,native⟩ &&
  nativeStep captured.membership { guards with nativeTruth := .unknown } native == ⟨.unknown,native⟩ &&
  nativeStep captured.membership { guards with pTruth := .old } native == ⟨.old,native⟩ &&
  nativeStep captured.membership { guards with pTruth := .unknown } native == ⟨.unknown,native⟩ &&
  (nativeStep captured.membership guards native).effect == .converted &&
  replayImage converted == (.cleanup,false,none,none,[],[],[11,12],[],1) &&
  retainedImage converted == (1,64,31,33,32,control,observed,0,0) &&
  converted.actualR == some 61 && converted.path == [parent,b,descendant] &&
  (nativeStep captured.membership guards converted).effect == .drained 11 &&
  replayImage drainedFirst == (.cleanup,false,none,none,[],[],[12],[11],1) &&
  (nativeStep captured.membership guards drainedFirst).effect == .drained 12 &&
  replayImage drainedSecond == (.cleanup,false,none,none,[],[],[],[11,12],1) &&
  (nativeStep captured.membership guards drainedSecond).effect == .pending &&
  replayImage pending == (.pending,false,none,none,[],[],[],[11,12],1) &&
  pending.actualR == none && pending.path == [] &&
  nativeStep captured.membership guards pending == ⟨.pending,pending⟩ &&
  retainedImage pending == (1,64,31,33,32,control,observed,0,0) &&
  nativeStep captured.membership { guards with nativeTruth := .unknown } drainedFirst ==
    ⟨.unknown,drainedFirst⟩ &&
  ([{ guards with currentBasis := false },{ guards with roles := false },
    { guards with sourceCursor := false }] : List NativeGuards).all
    (fun g => nativeStep captured.membership g native == ⟨.blocked,native⟩) &&
  nativeStep (.complete []) guards native == ⟨.unchanged,native⟩ &&
  nativeStep (.unreadable) guards native == ⟨.blocked,native⟩ &&
  nativeStep (row { fact with payload := { fact.payload with source := { source with backing := .retained 11 } } })
    guards native == ⟨.blocked,native⟩ &&
  nativeStep (row { fact with sourceAvailable := false }) guards native == ⟨.blocked,native⟩ &&
  nativeStep captured.membership guards { native with both := [11,11] } ==
    ⟨.blocked,{ native with both := [11,11] }⟩ &&
  nativeStep captured.membership guards { drainedFirst with cleanup := [11,12] } ==
    ⟨.blocked,{ drainedFirst with cleanup := [11,12] }⟩

private def unrelatedR : Native :=
  { native with
    path := [parent,sibling], actualR := some 62,
    control := { control with diagnosticPath := [parent,b,descendant] } }
private def rEqualsT0 : Native :=
  { native with actualR := some 52, control := { control with diagnosticPath := [parent,b,descendant] } }
private def bothContain : Native :=
  { native with control := { control with diagnosticPath := [parent,b] } }

-- F06: actual R alone controls retirement; the original H1 tuple is immutable.
def h1Cases : Bool :=
  nativeStep captured.membership guards unrelatedR == ⟨.unchanged,unrelatedR⟩ &&
  (nativeStep captured.membership guards native).effect == .converted &&
  (nativeStep captured.membership guards native).state.control ==
    ⟨51,52,[parent,sibling],53,[54,55],8,56,57,58,59,60⟩ &&
  ([rEqualsT0,bothContain] : List Native).all (fun n =>
    (nativeStep captured.membership guards n).effect == .converted &&
    replayImage (nativeStep captured.membership guards n).state ==
      (.cleanup,false,none,none,[],[],[11,12],[],1) &&
    (nativeStep captured.membership guards n).state.control == n.control) &&
  retainedImage pending == (1,64,31,33,32,control,observed,0,0) &&
  (nativeStep captured.membership guards unrelatedR).state.prebaseFetches == 0 &&
  ([some 101,some 102,none] : List (Option Nat)).all (fun terminal =>
    let n := { native with observations := { observed with actualTerminal := terminal } }
    (nativeStep captured.membership guards n).state.observations ==
      ⟨[21],[22],23,[24],[25],[26],terminal,some 28⟩) &&
  select { selection with candidates := [blocked] } == .pending

-- F07: nonempty controls make preservation distinguish event synthesis and suppression.
def noPublicInvalidCases : Bool :=
  ([observed,emptyObserved] : List Observations).all (fun o =>
    (capture { journal with observations := o } captureRequest).journal.observations == o &&
    (evaluateSelection { selection with observations := o }).retained.observations == o &&
    (nativeStep captured.membership guards { native with observations := o }).state.observations == o) &&
  (capture journal captureRequest).journal.observations ==
    ⟨[21],[22],23,[24],[25],[26],some 27,some 28⟩ &&
  ([Acquisition.direct,.staging,.entry] : List Acquisition).all (fun mode =>
    capture journal { captureRequest with probeInput := { acquired with acquisition := mode } } ==
      ⟨.noProof,journal⟩) &&
  (probe { acquired with acquisition := .archivePrefix }).reason == some .positionZeroChunk &&
  (nativeStep captured.membership { guards with nativeTruth := .old } native).state.q == some 10 &&
  (nativeStep captured.membership { guards with nativeTruth := .old } native).state.maps == [62,63] &&
  (nativeStep captured.membership guards native).state.skippedExecutions == 0 &&
  (nativeStep captured.membership guards native).state.prebaseFetches == 0 &&
  (evaluateSelection selection).retained.candidates.map Candidate.assurance ==
    [.conditionalImportedBase,.conditionalImportedBase,.conditionalImportedBase]

set_option maxRecDepth 8192 in
set_option maxHeartbeats 800000 in
private theorem predicateCases_checked : predicateCases = true := by decide
set_option maxRecDepth 8192 in
set_option maxHeartbeats 800000 in
private theorem qualificationCases_checked : qualificationCases = true := by decide
set_option maxRecDepth 8192 in
set_option maxHeartbeats 800000 in
private theorem selectionCases_checked : selectionCases = true := by decide
set_option maxRecDepth 8192 in
set_option maxHeartbeats 800000 in
private theorem captureCases_checked : captureCases = true := by decide
set_option maxRecDepth 8192 in
set_option maxHeartbeats 800000 in
private theorem dispositionCases_checked : dispositionCases = true := by decide
set_option maxRecDepth 8192 in
set_option maxHeartbeats 800000 in
private theorem h1Cases_checked : h1Cases = true := by decide
set_option maxRecDepth 8192 in
set_option maxHeartbeats 800000 in
private theorem noPublicInvalidCases_checked : noPublicInvalidCases = true := by decide

/-- Registered finite proposed-design evidence, conditional on the stated inputs. -/
theorem recovery_core_contract :
    predicateCases = true ∧ qualificationCases = true ∧ selectionCases = true ∧
    captureCases = true ∧ dispositionCases = true ∧ h1Cases = true ∧
    noPublicInvalidCases = true :=
  ⟨predicateCases_checked, qualificationCases_checked, selectionCases_checked,
    captureCases_checked, dispositionCases_checked, h1Cases_checked,
    noPublicInvalidCases_checked⟩

end RubinFormal.RecoveryCore
