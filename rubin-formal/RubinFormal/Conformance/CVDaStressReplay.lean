import RubinFormal.Conformance.CVDaStressVectors

namespace RubinFormal.Conformance

private def natOptEq (lhs rhs : Option Nat) : Bool :=
  lhs == rhs

private def boolOptEq (lhs rhs : Option Bool) : Bool :=
  lhs == rhs

private def listNatOptEq (lhs rhs : Option (List Nat)) : Bool :=
  lhs == rhs

private def evalDaStress (v : CVDaStressVector) : Bool :=
  if v.op == "compact_prefetch_caps" then
    match v.peerStreamsBps, v.perPeerBps, v.globalBps,
          v.expectPeerExceeded, v.expectGlobalExceeded,
          v.expectQualityPenalty, v.expectDisconnect with
    | some streams, some perPeer, some globalBps, some expPeer, some expGlobal, some expPenalty, some expDisc =>
        let peerExceeded := streams.any (fun x => x > perPeer)
        let totalBps := streams.foldl (· + ·) 0
        let globalExceeded := totalBps > globalBps
        let qualityPenalty := peerExceeded || globalExceeded
        let disconnect := false
        peerExceeded == expPeer
          && globalExceeded == expGlobal
          && qualityPenalty == expPenalty
          && disconnect == expDisc
    | _, _, _, _, _, _, _ => false
  else if v.op == "compact_orphan_limits" then
    match v.perPeerLimit, v.perDaIdLimit, v.globalLimit,
          v.currentPeerBytes, v.currentDaIdBytes, v.currentGlobalBytes,
          v.incomingChunkBytes, v.expectAdmit with
    | some perPeerLimit, some perDaIdLimit, some globalLimit,
      some currentPeerBytes, some currentDaIdBytes, some currentGlobalBytes,
      some incomingChunkBytes, some expAdmit =>
        let admit :=
          currentPeerBytes + incomingChunkBytes <= perPeerLimit
            && currentDaIdBytes + incomingChunkBytes <= perDaIdLimit
            && currentGlobalBytes + incomingChunkBytes <= globalLimit
        admit == expAdmit
    | _, _, _, _, _, _, _, _ => false
  else if v.op == "compact_orphan_storm" then
    match v.globalLimit, v.currentGlobalBytes, v.incomingHasCommit,
          v.recoverySuccessRate, v.observationMinutes, v.expectFillPct,
          v.expectStormMode, v.expectAdmit, v.expectRollback with
    | some globalLimit, some currentGlobalBytes, some incomingHasCommit,
      some recoverySuccessRate, some observationMinutes, some expectFillPct,
      some expectStormMode, some expectAdmit, some expectRollback =>
        let fillPct := ((currentGlobalBytes * 100) + (globalLimit / 2)) / globalLimit
        let stormMode := fillPct >= 90
        let admit := (!stormMode) || incomingHasCommit
        let rollback := stormMode && incomingHasCommit && recoverySuccessRate < 95 && observationMinutes >= 10
        fillPct == expectFillPct
          && stormMode == expectStormMode
          && admit == expectAdmit
          && rollback == expectRollback
    | _, _, _, _, _, _, _, _, _ => false
  else if v.op == "compact_pinned_accounting" then
    match v.capBytes, v.currentPinnedPayloadBytes, v.incomingPayloadBytes,
          v.incomingCommitOverheadBytes, v.expectCountedBytes,
          v.expectIgnoredOverheadBytes, v.expectAdmit with
    | some capBytes, some currentPinnedPayloadBytes, some incomingPayloadBytes,
      some incomingCommitOverheadBytes, some expectCountedBytes,
      some expectIgnoredOverheadBytes, some expectAdmit =>
        let countedBytes := currentPinnedPayloadBytes + incomingPayloadBytes
        let admit := countedBytes <= capBytes
        countedBytes == expectCountedBytes
          && incomingCommitOverheadBytes == expectIgnoredOverheadBytes
          && admit == expectAdmit
    | _, _, _, _, _, _, _ => false
  else if v.op == "compact_chunk_count_cap" then
    match v.maxDaChunkCount, v.chunkCount, v.expectErr with
    | some maxDaChunkCount, some chunkCount, expectErr =>
        if v.expectOk then
          chunkCount <= maxDaChunkCount
        else
          chunkCount > maxDaChunkCount && expectErr == some "TX_ERR_PARSE"
    | _, _, _ => false
  else
    false

def cvDaStressVectorsPass : Bool :=
  cvDaStressVectors.all evalDaStress

theorem cv_da_stress_vectors_pass : cvDaStressVectorsPass = true := by
  native_decide

end RubinFormal.Conformance
