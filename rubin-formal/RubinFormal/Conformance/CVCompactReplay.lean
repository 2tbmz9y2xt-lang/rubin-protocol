import Std
import RubinFormal.Conformance.CVCompactVectors
import RubinFormal.TxParseV2

namespace RubinFormal.Conformance

open RubinFormal
open TxV2

private def satSub (a b : Nat) : Nat :=
  if a >= b then a - b else 0

private def toNatClamp0_100 (x : Int) : Nat :=
  if x < 0 then 0 else if x > 100 then 100 else Int.toNat x

private def compactSizeLen (n : Nat) : Nat :=
  if n < 253 then 1 else if n <= 0xffff then 3 else if n <= 0xffffffff then 5 else 9

private def rotl64 (x : UInt64) (b : UInt64) : UInt64 :=
  (x <<< b) ||| (x >>> (64 - b))

private def sipRound (v0 v1 v2 v3 : UInt64) : (UInt64 × UInt64 × UInt64 × UInt64) :=
  let v0 := v0 + v1
  let v1 := rotl64 v1 13
  let v1 := v1 ^^^ v0
  let v0 := rotl64 v0 32
  let v2 := v2 + v3
  let v3 := rotl64 v3 16
  let v3 := v3 ^^^ v2
  let v0 := v0 + v3
  let v3 := rotl64 v3 21
  let v3 := v3 ^^^ v0
  let v2 := v2 + v1
  let v1 := rotl64 v1 17
  let v1 := v1 ^^^ v2
  let v2 := rotl64 v2 32
  (v0, v1, v2, v3)

private def u8sToU64le (xs : Array UInt8) : UInt64 :=
  Id.run <| do
    let mut acc : UInt64 := 0
    for i in [0:8] do
      acc := acc ||| ((UInt64.ofNat (xs.get! i).toNat) <<< (UInt64.ofNat (8 * i)))
    return acc

private def siphash24 (k0 k1 : UInt64) (msg : Bytes) : UInt64 :=
  Id.run <| do
    let mut v0 : UInt64 := 0x736f6d6570736575 ^^^ k0
    let mut v1 : UInt64 := 0x646f72616e646f6d ^^^ k1
    let mut v2 : UInt64 := 0x6c7967656e657261 ^^^ k0
    let mut v3 : UInt64 := 0x7465646279746573 ^^^ k1

    let data := msg.data
    let mut i : Nat := 0
    while i + 8 ≤ data.size do
      let m := u8sToU64le (data.extract i (i + 8))
      v3 := v3 ^^^ m
      let (a0, a1, a2, a3) := sipRound v0 v1 v2 v3
      let (b0, b1, b2, b3) := sipRound a0 a1 a2 a3
      v0 := b0; v1 := b1; v2 := b2; v3 := b3
      v0 := v0 ^^^ m
      i := i + 8

    let b : UInt64 := (UInt64.ofNat data.size) <<< 56
    let mut m : UInt64 := b
    let tail := data.extract i data.size
    for j in [0:tail.size] do
      m := m ||| ((UInt64.ofNat (tail.get! j).toNat) <<< (UInt64.ofNat (8 * j)))

    v3 := v3 ^^^ m
    let (a0, a1, a2, a3) := sipRound v0 v1 v2 v3
    let (b0, b1, b2, b3) := sipRound a0 a1 a2 a3
    v0 := b0; v1 := b1; v2 := b2; v3 := b3
    v0 := v0 ^^^ m

    v2 := v2 ^^^ 0xff
    for _ in [0:4] do
      let (c0, c1, c2, c3) := sipRound v0 v1 v2 v3
      v0 := c0; v1 := c1; v2 := c2; v3 := c3

    return v0 ^^^ v1 ^^^ v2 ^^^ v3

private def shortId (wtxid : Bytes) (nonce1 nonce2 : UInt64) : Bytes :=
  Id.run <| do
    let h := siphash24 nonce1 nonce2 wtxid
    let mut out : ByteArray := ByteArray.empty
    for i in [0:6] do
      out := out.push (UInt8.ofNat (((h >>> (UInt64.ofNat (8 * i))) &&& 0xff).toNat))
    return out

private def missingTxIndices (txCount : Nat) (prefilled mempool : List Nat) : List Nat :=
  let present := (prefilled ++ mempool).eraseDups
  (List.range txCount).filter (fun i => !(present.contains i))

private def scoreEventDelta (e : String) : Int :=
  if e == "reconstruct_no_getblocktxn" then 2
  else if e == "getblocktxn_succeeded_first" then 1
  else if e == "prefetch_completed_before_block" then 1
  else if e == "incomplete_set" then -5
  else if e == "getblocktxn_required" then -3
  else if e == "full_block_required" then -10
  else if e == "prefetch_rate_cap_exceeded" then -2
  else 0

private def applyScoreEvents (start : Nat) (events : List String) (graceActive : Bool) : Nat :=
  let startI : Int := Int.ofNat start
  let totalDelta : Int :=
    events.foldl (fun acc ev =>
      let d := scoreEventDelta ev
      if graceActive then acc + (d / 2) else acc + d
    ) 0
  toNatClamp0_100 (startI + totalDelta)

private def peerModeFromScore (score : Nat) : Nat :=
  if score < 40 then 0 else if score < 75 then 1 else 2

private def sendcmpctMode (p : CVCompactPhase) : Nat :=
  if p.inIbd then 0
  else if p.warmupDone && p.missRatePct < 1 && p.missRateBlocks <= 2 then 2
  else 0

private def orphanAdmit (current incoming cap : Nat) : Bool :=
  current + incoming <= cap

private def isCommitBearing (containsCommit containsChunkForKnownCommit containsBlockWithCommit : Bool) : Bool :=
  containsCommit || containsChunkForKnownCommit || containsBlockWithCommit

private def stormMode (fillPct triggerPct : Nat) : Bool :=
  fillPct >= triggerPct

private def evictionKeyLT (a b : CVCompactEvictionEntry) : Bool :=
  let aw := a.wireBytes
  let bw := b.wireBytes
  let aNum := a.fee * bw
  let bNum := b.fee * aw
  if aNum != bNum then aNum < bNum
  else if a.receivedTime != b.receivedTime then a.receivedTime < b.receivedTime
  else a.daId < b.daId

private def insertEvict (x : CVCompactEvictionEntry) : List CVCompactEvictionEntry → List CVCompactEvictionEntry
  | [] => [x]
  | y :: ys =>
      if evictionKeyLT x y then x :: y :: ys else y :: insertEvict x ys

private def sortEvict : List CVCompactEvictionEntry → List CVCompactEvictionEntry
  | [] => []
  | x :: xs => insertEvict x (sortEvict xs)

private def evictOrder (entries : List CVCompactEvictionEntry) : List String :=
  (sortEvict entries).map (·.daId)

private def insertChunkSet (haveChunks : List Nat) (idx : Nat) : List Nat :=
  if haveChunks.contains idx then haveChunks else haveChunks.concat idx

private def isCompleteSet (chunkCount : Nat) (haveChunks : List Nat) : Bool :=
  (List.range chunkCount).all (fun i => haveChunks.contains i)

private def compactStateMachineEval
    (chunkCount : Nat)
    (initialChunks : List Nat)
    (events : List CVCompactStateMachineEvent) :
    (String × Bool × Bool × Nat × Nat × Option (List Bool)) :=
  Id.run <| do
    let ttlInit : Nat := 3
    let mut commitSeen : Bool := false
    let mut pinned : Bool := false
    let mut evicted : Bool := false
    let mut ttl : Nat := 0
    let mut ttlResets : Nat := 0
    let mut haveChunks : List Nat := initialChunks.eraseDups
    let mut checks : List Bool := []

    for ev in events do
      match ev with
      | .commit =>
          commitSeen := true
          pinned := false
          ttl := ttlInit
          ttlResets := ttlResets + 1
      | .chunk idx =>
          haveChunks := insertChunkSet haveChunks idx
          if commitSeen && isCompleteSet chunkCount haveChunks then
            pinned := true
      | .tick blocks =>
          if commitSeen && !evicted then
            ttl := satSub ttl blocks
            if ttl == 0 && !(isCompleteSet chunkCount haveChunks) then
              evicted := true
              pinned := false
      | .checkblock =>
          checks := checks.concat (commitSeen && isCompleteSet chunkCount haveChunks)

    let st :=
      if evicted then "EVICTED"
      else if commitSeen && isCompleteSet chunkCount haveChunks then "C"
      else if commitSeen then "B"
      else "A"
    return (st, pinned, evicted, ttl, ttlResets, if checks.isEmpty then none else some checks)

private def telemetryMissingFields (t : CVCompactTelemetry) : List String :=
  (if t.peerQualityScore.isNone then ["peer_quality_score"] else [])
  ++ (if t.recoverySuccessRatePct.isNone then ["recovery_success_rate"] else [])

def evalCompact (v : CVCompactVector) : (Bool × Option String) :=
  if v.op == "parse_tx" then
    match v.tx with
    | none => (false, some "TX_ERR_PARSE")
    | some txBytes =>
        let r := TxV2.parseTx txBytes
        if v.expectOk then
          match v.expectTxid, v.expectWtxid with
          | some expTxid, some expWtxid =>
              if r.ok && r.txid == some expTxid && r.wtxid == some expWtxid then
                (true, none)
              else
                (false, some "TX_ERR_PARSE")
          | _, _ => (false, some "TX_ERR_PARSE")
        else
          match r.err with
          | none => (false, some "TX_ERR_PARSE")
          | some e => (false, some e.toString)
  else if v.op == "compact_shortid" then
    match v.wtxid, v.nonce1, v.nonce2, v.expectShortId with
    | some w, some n1, some n2, some exp =>
        let got := shortId w n1 n2
        (got == exp, if got == exp then none else some "TX_ERR_PARSE")
    | _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_collision_fallback" then
    match v.missingIndices, v.getblocktxnOk, v.expectRequestGetblocktxn, v.expectRequestFullBlock, v.expectPenalizePeer with
    | some miss, some okGet, some expReqGet, some expReqFull, some expPen =>
        let reqGet := !miss.isEmpty
        let reqFull := reqGet && (!okGet)
        let pen := false
        let ok := (expReqGet == reqGet) && (expReqFull == reqFull) && (expPen == pen)
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_witness_roundtrip" then
    match v.suiteId, v.pubkeyLength, v.sigLength, v.expectWireBytes, v.expectRoundtripOk with
    | some sid, some pk, some sg, some expWire, some expOk =>
        let wire := 1 + compactSizeLen pk + pk + compactSizeLen sg + sg
        let ok := (sid < 256) && (wire == expWire) && expOk
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_batch_verify" then
    match v.batchSize, v.invalidIndices, v.expectBatchOk, v.expectFallback, v.expectInvalidIndices with
    | some bs, some bad, some expOk, some expFallback, some expBad =>
        let ok := (bs > 0) && (bad == expBad) && (expOk == bad.isEmpty) && (expFallback == (!bad.isEmpty))
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_prefill_roundtrip" then
    match v.txCount, v.prefilledIndices, v.mempoolIndices, v.expectMissingIndices, v.expectReconstructed, v.expectRequestFullBlock with
    | some n, some pre, some mem, some expMissing, some expRec, some expReqFull =>
        let miss := missingTxIndices n pre mem
        let ok := (miss == expMissing) && (expRec == true) && (expReqFull == false)
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_state_machine" then
    match v.chunkCount, v.initialChunks, v.events, v.expectFinalState with
    | some cc, some init, some evs, some expSt =>
        let (st, pinned, evicted, ttl, resets, checks) := compactStateMachineEval cc init evs
        let checksOk :=
          match v.expectCheckblockResults, checks with
          | none, none => true
          | some exp, some got => exp == got
          | _, _ => false
        let pinnedOk := match v.expectPinned with | none => true | some exp => pinned == exp
        let evictedOk := match v.expectEvicted with | none => true | some exp => evicted == exp
        let ttlOk := match v.expectTtl with | none => true | some exp => ttl == exp
        let resetsOk := match v.expectTtlResetCount with | none => true | some exp => resets == exp
        let ok := st == expSt && pinnedOk && evictedOk && ttlOk && resetsOk && checksOk
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_orphan_limits" then
    match v.currentPeerBytes, v.currentDaIdBytes, v.currentGlobalBytes, v.incomingChunkBytes, v.expectAdmit with
    | some peerB, some daB, some globB, some inB, some expAdmit =>
        let admit :=
          orphanAdmit peerB inB 4194304 &&
          orphanAdmit daB inB 8388608 &&
          orphanAdmit globB inB 67108864
        let ok := admit == expAdmit
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_sendcmpct_modes" then
    match v.phases, v.expectModes with
    | some phases, some exp =>
        let got := phases.map sendcmpctMode
        let ok := got == exp
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_peer_quality" then
    match v.startScore, v.qualityEvents, v.expectScore, v.expectMode with
    | some start, some evs, some expScore, some expMode =>
        let score := applyScoreEvents start evs false
        let mode := peerModeFromScore score
        let ok := score == expScore && mode == expMode
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_prefetch_caps" then
    match v.peerStreamsBps, v.expectPeerExceeded, v.expectGlobalExceeded, v.expectQualityPenalty, v.expectDisconnect with
    | some streams, some expPeer, some expGlobal, some expPenalty, some expDisc =>
        let peerExceeded := streams.any (fun x => x > 4000000)
        let globalExceeded := (streams.foldl (· + ·) 0) > 32000000
        let penalty := peerExceeded || globalExceeded
        let disc := false
        let ok := peerExceeded == expPeer && globalExceeded == expGlobal && penalty == expPenalty && disc == expDisc
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_telemetry_rate" then
    match v.completedSets, v.totalSets, v.expectRateNumer, v.expectRateDenom with
    | some done, some total, some expN, some expD =>
        if total == 0 then
          (false, some "TX_ERR_PARSE")
        else
          let ok := (done == expN) && (total == expD)
          (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_grace_period" then
    match v.startScore, v.graceEvents, v.elapsedBlocks, v.gracePeriodBlocks, v.expectScore, v.expectGraceActive, v.expectDisconnect with
    | some start, some evs, some elapsed, some graceBlocks, some expScore, some expGrace, some expDisc =>
        let grace := elapsed < graceBlocks
        let score := applyScoreEvents start evs grace
        let disc := (!grace) && (score < 20)
        let ok := score == expScore && grace == expGrace && disc == expDisc
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_telemetry_fields" then
    match v.telemetry, v.expectMissingFields with
    | some tel, expMissing =>
        let missing := telemetryMissingFields tel
        if v.expectOk then
          (missing.isEmpty && expMissing.isNone, if missing.isEmpty then none else some "TX_ERR_PARSE")
        else
          let ok := expMissing == some missing
          -- non-error soft validation: ok=false is not a protocol error
          (ok, none)
    | _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_orphan_storm" then
    match v.currentGlobalBytes, v.globalLimit, v.incomingChunkBytes, v.incomingHasCommit, v.recoverySuccessRatePct, v.observationMinutes,
          v.expectStormMode, v.expectAdmit, v.expectRollback with
    | some cur, some lim, some _inc, some hasCommit, some rsr, some mins, some expStorm, some expAdmit, some expRb =>
        let fillPct := (cur * 100) / lim
        let storm := fillPct >= 90
        let admit := (!storm) || hasCommit
        let rollback := storm && hasCommit && (rsr < 95) && (mins >= 10)
        let ok := (storm == expStorm) && (admit == expAdmit) && (rollback == expRb)
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_eviction_tiebreak" then
    match v.entries, v.expectEvictOrder with
    | some es, some exp =>
        let got := evictOrder es
        let ok := got == exp
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_a_to_b_retention" then
    match v.chunkCount, v.initialChunks, v.commitArrives, v.expectState, v.expectMissingChunks, v.expectRetainedChunks, v.expectDiscardedChunks, v.expectPrefetchTargets with
    | some cc, some init, some commitArr, some expSt, some expMiss, some expRet, some expDisc, some expPref =>
        let miss := (List.range cc).filter (fun i => !(init.contains i))
        let retained := init
        let discarded : List Nat := []
        let prefetch := miss
        let st := if commitArr then "B" else "A"
        let ok := st == expSt && miss == expMiss && retained == expRet && discarded == expDisc && prefetch == expPref
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_duplicate_commit" then
    match v.commits, v.daId, v.expectRetainedPeer, v.expectDuplicatesDropped, v.expectPenalizedPeers, v.expectReplaced with
    | some commits, some daId, some expPeer, some expDropped, some expPenalized, some expReplaced =>
        let same := commits.filter (fun c => c.daId == daId)
        let retained := same.head?.map (·.peer)
        let dropped := if same.length > 0 then same.length - 1 else 0
        let penalized := (same.drop 1).map (·.peer)
        let replaced := false
        let ok := retained == some expPeer && dropped == expDropped && penalized == expPenalized && replaced == expReplaced
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_total_fee" then
    match v.commitFee, v.chunkFees, v.expectTotalFee with
    | some cf, some fees, some exp =>
        let got := fees.foldl (· + ·) cf
        let ok := got == exp
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_pinned_accounting" then
    match v.capBytes, v.currentPinnedPayloadBytes, v.incomingPayloadBytes, v.incomingCommitOverheadBytes,
          v.expectCountedBytes, v.expectIgnoredOverheadBytes, v.expectAdmit with
    | some cap, some cur, some incPayload, some incOver, some expCounted, some expIgnored, some expAdmit =>
        let counted := cur + incPayload
        let admit := counted <= cap
        let ok := (counted == expCounted) && (incOver == expIgnored) && (admit == expAdmit)
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_storm_commit_bearing" then
    match v.orphanPoolFillPct, v.stormTriggerPct, v.containsCommit, v.containsChunkForKnownCommit, v.containsBlockWithCommit,
          v.expectStormMode, v.expectCommitBearing, v.expectPrioritize, v.expectAdmit with
    | some fill, some trig, some c1, some c2, some c3, some expStorm, some expCb, some expPrio, some expAdmit =>
        let storm := stormMode fill trig
        let cb := isCommitBearing c1 c2 c3
        let prio := storm && cb
        let admit := (!storm) || cb
        let ok := storm == expStorm && cb == expCb && prio == expPrio && admit == expAdmit
        (ok, if ok then none else some "TX_ERR_PARSE")
    | _, _, _, _, _, _, _, _, _ => (false, some "TX_ERR_PARSE")
  else if v.op == "compact_chunk_count_cap" then
    match v.chunkCount with
    | none => (false, some "TX_ERR_PARSE")
    | some cc =>
        if cc <= 61 then
          (true, none)
        else
          (false, some "TX_ERR_PARSE")
  else
    (false, some "TX_ERR_PARSE")

def compactVectorPass (v : CVCompactVector) : Bool :=
  if v.op == "compact_telemetry_fields" then
    (evalCompact v).1
  else
    let (ok, err) := evalCompact v
    if v.expectOk then
      ok && err.isNone
    else
      (!ok) && (err == v.expectErr)

def cvCompactVectorsPass : Bool :=
  cvCompactVectors_CV_COMPACT.all compactVectorPass

theorem cv_compact_vectors_pass : cvCompactVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
