import Std
import RubinFormal.SHA3_256
import RubinFormal.TxParseV2
import RubinFormal.Conformance.CVCompactVectors

namespace RubinFormal.Conformance

open RubinFormal
open TxV2
open SHA3

abbrev Bytes := ByteArray

namespace SipHash

@[inline] def rotl (x : UInt64) (n : Nat) : UInt64 :=
  x.rotateLeft (UInt64.ofNat (n % 64))

@[inline] def sipRound (v0 v1 v2 v3 : UInt64) : (UInt64 × UInt64 × UInt64 × UInt64) :=
  let v0 := v0 + v1
  let v1 := rotl v1 13
  let v1 := v1 ^^^ v0
  let v0 := rotl v0 32
  let v2 := v2 + v3
  let v3 := rotl v3 16
  let v3 := v3 ^^^ v2
  let v0 := v0 + v3
  let v3 := rotl v3 21
  let v3 := v3 ^^^ v0
  let v2 := v2 + v1
  let v1 := rotl v1 17
  let v1 := v1 ^^^ v2
  let v2 := rotl v2 32
  (v0, v1, v2, v3)

@[inline] def u64FromLeBytesAt (b : Bytes) (off : Nat) : UInt64 :=
  u64FromLeBytes
    (b.get! (off+0)) (b.get! (off+1)) (b.get! (off+2)) (b.get! (off+3))
    (b.get! (off+4)) (b.get! (off+5)) (b.get! (off+6)) (b.get! (off+7))

def tailBlock (msg : Bytes) (off : Nat) : UInt64 :=
  let b := msg.size
  let mut last : UInt64 := 0
  let tailLen := b - off
  for i in [0:tailLen] do
    let bi := UInt64.ofNat (msg.get! (off+i)).toNat
    last := last ||| (bi <<< (8*i))
  last := last ||| ((UInt64.ofNat b) <<< 56)
  last

def sipHash24 (k0 k1 : UInt64) (msg : Bytes) : UInt64 :=
  Id.run do
    let mut v0 : UInt64 := 0x736f6d6570736575 ^^^ k0
    let mut v1 : UInt64 := 0x646f72616e646f6d ^^^ k1
    let mut v2 : UInt64 := 0x6c7967656e657261 ^^^ k0
    let mut v3 : UInt64 := 0x7465646279746573 ^^^ k1

    let mut off : Nat := 0
    while off + 8 <= msg.size do
      let m := u64FromLeBytesAt msg off
      v3 := v3 ^^^ m
      for _ in [0:2] do
        let (a,b,c,d) := sipRound v0 v1 v2 v3
        v0 := a; v1 := b; v2 := c; v3 := d
      v0 := v0 ^^^ m
      off := off + 8

    let last := tailBlock msg off
    v3 := v3 ^^^ last
    for _ in [0:2] do
      let (a,b,c,d) := sipRound v0 v1 v2 v3
      v0 := a; v1 := b; v2 := c; v3 := d
    v0 := v0 ^^^ last

    v2 := v2 ^^^ 0xff
    for _ in [0:4] do
      let (a,b,c,d) := sipRound v0 v1 v2 v3
      v0 := a; v1 := b; v2 := c; v3 := d

    (v0 ^^^ v1 ^^^ v2 ^^^ v3)

def shortId (k0 k1 : UInt64) (wtxid : Bytes) : Bytes :=
  let h := sipHash24 k0 k1 wtxid
  let mut out : Bytes := ByteArray.empty
  for i in [0:6] do
    out := out.push (UInt8.ofNat ((h >>> (8*i)).toNat &&& 0xff))
  out

end SipHash

def compactSizeLen (n : Nat) : Nat :=
  if n < 253 then 1
  else if n <= 0xffff then 3
  else if n <= 0xffffffff then 5
  else 9

def witnessWireLen (suiteId pubLen sigLen : Nat) : Nat :=
  1 + compactSizeLen pubLen + pubLen + compactSizeLen sigLen + sigLen

structure CompactSet where
  chunkCount : Nat
  haveCommit : Bool
  chunks : List Nat
  ttl : Nat
  ttlResetCount : Nat
  evicted : Bool
deriving Repr

def TTL_BASE : Nat := 3

def normalizeChunks (chunkCount : Nat) (xs : List Nat) : List Nat :=
  let rec go (seen : List Nat) (rest : List Nat) : List Nat :=
    match rest with
    | [] => []
    | x::xs =>
      if x < chunkCount && !(seen.contains x) then
        x :: go (x::seen) xs
      else
        go seen xs
  go [] xs

def isComplete (s : CompactSet) : Bool :=
  s.haveCommit && (normalizeChunks s.chunkCount s.chunks).length == s.chunkCount

def stateLabel (s : CompactSet) : String :=
  if s.evicted then "EVICTED"
  else if isComplete s then "C"
  else if s.haveCommit then "B"
  else "A"

def pinned (s : CompactSet) : Bool :=
  (!s.evicted) && (s.haveCommit || (normalizeChunks s.chunkCount s.chunks).length > 0)

def applyEvent (s : CompactSet) (ev : CVCompactStateMachineEvent) : (CompactSet × Option Bool) :=
  match ev with
  | .commit =>
      ({ s with haveCommit := true, ttl := TTL_BASE, ttlResetCount := s.ttlResetCount + 1 }, none)
  | .chunk i =>
      ({ s with chunks := normalizeChunks s.chunkCount (s.chunks ++ [i]) }, none)
  | .tick blocks =>
      if s.evicted then (s, none) else
      let ttl' := if blocks >= s.ttl then 0 else s.ttl - blocks
      let evicted' := (ttl' == 0) && (!isComplete s)
      ({ s with ttl := ttl', evicted := evicted' }, none)
  | .checkblock =>
      (s, some (isComplete s))

def runStateMachine (chunkCount : Nat) (initialChunks : List Nat) (events : List CVCompactStateMachineEvent) :
    (CompactSet × List Bool) :=
  let init : CompactSet := {
    chunkCount := chunkCount,
    haveCommit := false,
    chunks := normalizeChunks chunkCount initialChunks,
    ttl := TTL_BASE,
    ttlResetCount := 0,
    evicted := false
  }
  let mut st := init
  let mut checks : List Bool := []
  for ev in events do
    let (st', r) := applyEvent st ev
    st := st'
    match r with
    | none => pure ()
    | some b => checks := checks ++ [b]
  (st, checks)

def PEER_CAP_BYTES : Nat := 4 * 1024 * 1024
def DA_ID_CAP_BYTES : Nat := 8 * 1024 * 1024
def GLOBAL_CAP_BYTES : Nat := 64 * 1024 * 1024

def orphanAdmit (peerBytes daIdBytes globalBytes incoming : Nat) : Bool :=
  (peerBytes + incoming <= PEER_CAP_BYTES) &&
  (daIdBytes + incoming <= DA_ID_CAP_BYTES) &&
  (globalBytes + incoming <= GLOBAL_CAP_BYTES)

def selectSendCmpctMode (p : CVCompactPhase) : Nat :=
  if p.inIbd then 0
  else if p.warmupDone && p.missRatePct <= 1 && p.missRateBlocks <= 2 then 2
  else 0

def applyQualityEvent (score : Nat) (ev : String) : Nat :=
  let dec (n : Nat) : Nat := if score <= n then 0 else score - n
  if ev == "reconstruct_no_getblocktxn" then score
  else if ev == "getblocktxn_required" then dec 3
  else if ev == "full_block_required" then dec 8
  else score

def qualityMode (score : Nat) : Nat :=
  if score >= 60 then 2 else 0

def PREFETCH_PEER_CAP_BPS : Nat := 4_000_000
def PREFETCH_GLOBAL_CAP_BPS : Nat := 32_000_000

def prefetchCapsCheck (streams : List Nat) : (Bool × Bool × Bool × Bool) :=
  let peerExceeded := streams.any (fun bps => bps > PREFETCH_PEER_CAP_BPS)
  let total := streams.foldl (· + ·) 0
  let globalExceeded := total > PREFETCH_GLOBAL_CAP_BPS
  let qualityPenalty := peerExceeded || globalExceeded
  let disconnect := total > (2 * PREFETCH_GLOBAL_CAP_BPS)
  (peerExceeded, globalExceeded, qualityPenalty, disconnect)

def telemetryRateOk (completed total numer denom : Nat) : Bool :=
  completed * denom == numer * total

def applyGraceEvent (score : Nat) (graceActive : Bool) (ev : String) : Nat :=
  if ev != "full_block_required" then score
  else
    if graceActive then
      if score <= 5 then 0 else score - 5
    else
      if score <= 6 then 0 else score - 6

def missingTelemetryFields (t : CVCompactTelemetry) : List String :=
  let mut out : List String := []
  let req (name : String) (x : Option α) : Unit :=
    if x.isNone then out := out ++ [name] else ()
  req "shortid_collision_count" t.shortidCollisionCount
  req "shortid_collision_blocks" t.shortidCollisionBlocks
  req "shortid_collision_peers" t.shortidCollisionPeers
  req "da_mempool_fill_pct" t.daMempoolFillPct
  req "orphan_pool_fill_pct" t.orphanPoolFillPct
  req "miss_rate_bytes_L1" t.missRateBytesL1
  req "miss_rate_bytes_DA" t.missRateBytesDa
  req "partial_set_count" t.partialSetCount
  req "partial_set_age_p95" t.partialSetAgeP95
  req "prefetch_latency_ms" t.prefetchLatencyMs
  req "peer_quality_score" t.peerQualityScore
  req "recovery_success_rate" t.recoverySuccessRatePct
  out

def stormMode (globalLimit currentGlobal : Nat) (triggerPct : Nat := 90) : Bool :=
  currentGlobal * 100 >= globalLimit * triggerPct

def orphanStormDecision (globalLimit currentGlobal incomingBytes : Nat) (incomingHasCommit : Bool)
    (recoverySuccessRatePct observationMinutes : Nat) : (Bool × Bool × Bool) :=
  let storm := stormMode globalLimit currentGlobal 90
  let admit := if storm then incomingHasCommit else (currentGlobal + incomingBytes <= globalLimit)
  let rollback := admit && (recoverySuccessRatePct < 95) && (observationMinutes >= 10)
  (storm, admit, rollback)

def ltEvict (a b : CVCompactEvictionEntry) : Bool :=
  let left := a.fee * b.wireBytes
  let right := b.fee * a.wireBytes
  if left != right then left < right else a.receivedTime < b.receivedTime

def sortEvict (xs : List CVCompactEvictionEntry) : List CVCompactEvictionEntry :=
  xs.qsort ltEvict

def duplicateCommitDecision (commits : List CVCompactCommitEntry) :
    (Option String × Nat × List String × Bool) :=
  match commits with
  | [] => (none, 0, [], false)
  | c0 :: rest =>
      (some c0.peer, rest.length, rest.map (·.peer), false)

def checkCompactVector (v : CVCompactVector) : Bool :=
  match v.op with
  | "compact_shortid" =>
      match v.wtxid, v.nonce1, v.nonce2, v.expectShortId with
      | some w, some n1, some n2, some exp =>
          v.expectOk && (SipHash.shortId n1 n2 w == exp)
      | _, _, _, _ => false
  | "compact_collision_fallback" =>
      let missing := v.missingIndices.getD []
      let getOk := v.getblocktxnOk.getD false
      let reqGet := missing.length > 0
      let reqFull := reqGet && (!getOk)
      v.expectOk &&
      v.expectRequestGetblocktxn == some reqGet &&
      v.expectRequestFullBlock == some reqFull &&
      v.expectPenalizePeer == some false
  | "parse_tx" =>
      match v.tx with
      | none => false
      | some tx =>
        let r := TxV2.parseTx tx
        if v.expectOk then
          match r.txid, r.wtxid, v.expectTxid, v.expectWtxid with
          | some txid, some wtxid, some expTxid, some expWtxid =>
              r.ok == true && txid == expTxid && wtxid == expWtxid
          | _, _, _, _ => false
        else
          match r.err, v.expectErr with
          | some e, some exp => r.ok == false && e.toString == exp
          | _, _ => false
  | "compact_witness_roundtrip" =>
      let pubLen := v.pubkeyLength.getD 0
      let sigLen := v.sigLength.getD 0
      let wire := witnessWireLen (v.suiteId.getD 0) pubLen sigLen
      v.expectOk &&
      v.expectRoundtripOk == some true &&
      v.expectWireBytes == some wire
  | "compact_batch_verify" =>
      let invalid := v.invalidIndices.getD []
      let batchOk := invalid.isEmpty
      let fallback := !batchOk
      v.expectOk &&
      v.expectBatchOk == some batchOk &&
      v.expectFallback == some fallback &&
      v.expectInvalidIndices == some invalid
  | "compact_prefill_roundtrip" =>
      let txCount := v.txCount.getD 0
      let prefilled := v.prefilledIndices.getD []
      let mempool := v.mempoolIndices.getD []
      let allHave := (prefilled ++ mempool)
      let missing := (List.range txCount).filter (fun i => !(allHave.contains i))
      let reconstructed := missing == (v.blocktxnIndices.getD [])
      v.expectOk &&
      v.expectMissingIndices == some missing &&
      v.expectReconstructed == some reconstructed &&
      v.expectRequestFullBlock == some false
  | "compact_state_machine" =>
      let cc := v.chunkCount.getD 0
      let init := v.initialChunks.getD []
      let evs := v.events.getD []
      let (st, checks) := runStateMachine cc init evs
      let okChecks := match v.expectCheckblockResults with
        | none => true
        | some exp => exp == checks
      v.expectOk &&
      okChecks &&
      (v.expectFinalState.isNone || v.expectFinalState == some (stateLabel st)) &&
      (v.expectPinned.isNone || v.expectPinned == some (pinned st)) &&
      (v.expectEvicted.isNone || v.expectEvicted == some st.evicted) &&
      (v.expectTtl.isNone || v.expectTtl == some st.ttl) &&
      (v.expectTtlResetCount.isNone || v.expectTtlResetCount == some st.ttlResetCount)
  | "compact_orphan_limits" =>
      let admit := orphanAdmit (v.currentPeerBytes.getD 0) (v.currentDaIdBytes.getD 0) (v.currentGlobalBytes.getD 0)
        (v.incomingChunkBytes.getD 0)
      v.expectOk && v.expectAdmit == some admit
  | "compact_sendcmpct_modes" =>
      let modes := (v.phases.getD []).map selectSendCmpctMode
      v.expectOk && v.expectModes == some modes
  | "compact_peer_quality" =>
      let start := v.startScore.getD 0
      let final := (v.qualityEvents.getD []).foldl (fun s e => applyQualityEvent s e) start
      v.expectOk && v.expectScore == some final && v.expectMode == some (qualityMode final)
  | "compact_prefetch_caps" =>
      let (peerEx, globalEx, penalty, disc) := prefetchCapsCheck (v.peerStreamsBps.getD [])
      v.expectOk &&
      v.expectPeerExceeded == some peerEx &&
      v.expectGlobalExceeded == some globalEx &&
      v.expectQualityPenalty == some penalty &&
      v.expectDisconnect == some disc
  | "compact_telemetry_rate" =>
      let completed := v.completedSets.getD 0
      let total := v.totalSets.getD 1
      let numer := v.expectRateNumer.getD 0
      let denom := v.expectRateDenom.getD 1
      v.expectOk && telemetryRateOk completed total numer denom
  | "compact_chunk_count_cap" =>
      let cc := v.chunkCount.getD 0
      let cap : Nat := 61
      if cc > cap then
        v.expectOk == false && v.expectErr == some "TX_ERR_PARSE"
      else
        v.expectOk == true
  | "compact_grace_period" =>
      let grace := v.gracePeriodBlocks.getD 0
      let elapsed := v.elapsedBlocks.getD 0
      let graceActive := elapsed < grace
      let start := v.startScore.getD 0
      let final := (v.graceEvents.getD []).foldl (fun s e => applyGraceEvent s graceActive e) start
      let disconnect := (!graceActive) && (final == 0)
      v.expectOk &&
      v.expectGraceActive == some graceActive &&
      v.expectScore == some final &&
      v.expectDisconnect == some disconnect
  | "compact_telemetry_fields" =>
      match v.telemetry with
      | none => false
      | some t =>
          let missing := missingTelemetryFields t
          if v.expectOk then
            missing.isEmpty
          else
            v.expectMissingFields == some missing
  | "compact_orphan_storm" =>
      let (storm, admit, rollback) := orphanStormDecision
        (v.globalLimit.getD 0)
        (v.currentGlobalBytes.getD 0)
        (v.incomingChunkBytes.getD 0)
        (v.incomingHasCommit.getD false)
        (v.recoverySuccessRatePct.getD 0)
        (v.observationMinutes.getD 0)
      v.expectOk &&
      v.expectStormMode == some storm &&
      v.expectAdmit == some admit &&
      v.expectRollback == some rollback
  | "compact_eviction_tiebreak" =>
      let evicted := (sortEvict (v.entries.getD [])).map (·.daId)
      v.expectOk && v.expectEvictOrder == some evicted
  | "compact_a_to_b_retention" =>
      let cc := v.chunkCount.getD 0
      let retained := normalizeChunks cc (v.initialChunks.getD [])
      let missing := (List.range cc).filter (fun i => !(retained.contains i))
      v.expectOk &&
      v.expectState == some "B" &&
      v.expectRetainedChunks == some retained &&
      v.expectMissingChunks == some missing &&
      v.expectPrefetchTargets == some missing &&
      v.expectDiscardedChunks == some []
  | "compact_duplicate_commit" =>
      let (retainedPeer, dropped, penalized, replaced) := duplicateCommitDecision (v.commits.getD [])
      v.expectOk &&
      v.expectRetainedPeer == retainedPeer &&
      v.expectDuplicatesDropped == some dropped &&
      v.expectPenalizedPeers == some penalized &&
      v.expectReplaced == some replaced
  | "compact_total_fee" =>
      let total := (v.commitFee.getD 0) + (v.chunkFees.getD []).foldl (· + ·) 0
      v.expectOk && v.expectTotalFee == some total
  | "compact_pinned_accounting" =>
      let counted := (v.currentPinnedPayloadBytes.getD 0) + (v.incomingPayloadBytes.getD 0)
      let ignore := v.incomingCommitOverheadBytes.getD 0
      let admit := counted <= (v.capBytes.getD 0)
      v.expectOk &&
      v.expectCountedBytes == some counted &&
      v.expectIgnoredOverheadBytes == some ignore &&
      v.expectAdmit == some admit
  | "compact_storm_commit_bearing" =>
      let trig := v.stormTriggerPct.getD 0
      let fill := v.orphanPoolFillPct.getD 0
      let storm := fill >= trig
      let bearing := (v.containsCommit.getD false) || (v.containsChunkForKnownCommit.getD false) || (v.containsBlockWithCommit.getD false)
      let prioritize := storm && bearing
      let admit := prioritize
      v.expectOk &&
      v.expectStormMode == some storm &&
      v.expectCommitBearing == some bearing &&
      v.expectPrioritize == some prioritize &&
      v.expectAdmit == some admit
  | _ => false

def cvCompactVectorsPass : Bool :=
  cvCompactVectors_CV_COMPACT.all checkCompactVector

theorem cv_compact_vectors_pass : cvCompactVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

