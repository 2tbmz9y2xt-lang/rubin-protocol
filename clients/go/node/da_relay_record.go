package node

import (
	"bytes"
	"crypto/sha3"
	"sort"
)

// CompleteSetCandidates returns caller-owned COMPLETE_SET snapshots up to maxPayloadBytes.
func (s *DARelayState) CompleteSetCandidates(maxPayloadBytes uint64) []CompleteDASetCandidate {
	if s == nil || maxPayloadBytes == 0 {
		return nil
	}
	var candidates []CompleteDASetCandidate
	var payloadBytes uint64
	for _, record := range s.completeSetCandidateRecordsSnapshot() {
		if record.payloadBytes > maxPayloadBytes-payloadBytes {
			continue
		}
		candidate, ok := record.completeSetCandidate()
		if !ok {
			continue
		}
		candidates = append(candidates, candidate)
		payloadBytes += record.payloadBytes
	}
	return candidates
}

func (s *DARelayState) completeSetCandidateRecordsSnapshot() []daRelaySetRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	daIDs := make([][32]byte, 0, len(s.sets))
	for daID, record := range s.sets {
		if record.state == daRelayStateCompleteSet {
			daIDs = append(daIDs, daID)
		}
	}
	sort.Slice(daIDs, func(i, j int) bool {
		return bytes.Compare(daIDs[i][:], daIDs[j][:]) < 0
	})

	records := make([]daRelaySetRecord, 0, len(daIDs))
	for _, daID := range daIDs {
		records = append(records, s.sets[daID].cloneForStateMutation())
	}
	return records
}

func (r daRelaySetRecord) completeSetCandidate() (CompleteDASetCandidate, bool) {
	if r.commit.chunkCount == 0 || len(r.commit.txBytes) == 0 {
		return CompleteDASetCandidate{}, false
	}
	chunks := make([]CompleteDASetChunkCandidate, 0, r.commit.chunkCount)
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		chunk, ok := r.chunks[i]
		if !ok || len(chunk.txBytes) == 0 {
			return CompleteDASetCandidate{}, false
		}
		chunks = append(chunks, CompleteDASetChunkCandidate{Index: i, Tx: cloneBytes(chunk.txBytes)})
	}
	return CompleteDASetCandidate{
		DAID:         r.daID,
		PayloadBytes: r.payloadBytes,
		CommitTx:     cloneBytes(r.commit.txBytes),
		Chunks:       chunks,
	}, true
}

// advanceAcceptedSequenceLocked consumes exactly ONE value of the service-local
// accepted-sequence high-water for one successful nonduplicate MEMBER, and gives
// the record its FIRST member's value as receivedTime — a later member of the
// same record advances the high-water but never refreshes the record
// (RUBIN_COMPACT_BLOCKS.md Section 18.2).
//
// The add is checked BEFORE any field moves, so an exhausted space
// (high-water == 2^64-1, which the previous acceptance was still allowed to
// take) fails closed with the projected image untouched. A restarted service
// begins at zero, so the first member of a fresh process is 1.
func (s *DARelayState) advanceAcceptedSequenceLocked(record *daRelaySetRecord) error {
	next, err := checkedAddUint64(s.nextReceivedTime, 1)
	if err != nil {
		return err
	}
	s.nextReceivedTime = next
	if record.receivedTime == 0 {
		record.receivedTime = next
	}
	return nil
}

func (r daRelaySetRecord) missingChunkIndexes() []uint16 {
	if r.commit.chunkCount == 0 || r.state == daRelayStateCompleteSet {
		return nil
	}
	var missing []uint16
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		if _, ok := r.chunks[i]; !ok {
			missing = append(missing, i)
		}
	}
	return missing
}

func (r daRelaySetRecord) evictionAccounting() (daRelayEvictionAccounting, bool) {
	if r.state != daRelayStateCompleteSet || r.payloadBytes == 0 || r.wireBytes == 0 || r.receivedTime == 0 {
		return daRelayEvictionAccounting{}, false
	}
	return daRelayEvictionAccounting{
		daID:         r.daID,
		payloadBytes: r.payloadBytes,
		wireBytes:    r.wireBytes,
		receivedTime: r.receivedTime,
	}, true
}

func (r daRelaySetRecord) clone() daRelaySetRecord {
	return r.cloneWithPayloads(true)
}

func (r daRelaySetRecord) cloneForStateMutation() daRelaySetRecord {
	return r.cloneWithPayloads(false)
}

func (r daRelaySetRecord) cloneWithPayloads(copyPayloads bool) daRelaySetRecord {
	out := r
	if copyPayloads {
		out.commit.txBytes = nil
	}
	if r.chunks != nil {
		out.chunks = make(map[uint16]daRelayChunk, len(r.chunks))
		for index, chunk := range r.chunks {
			if copyPayloads {
				chunk.payload = cloneBytes(chunk.payload)
				chunk.txBytes = nil
			}
			out.chunks[index] = chunk
		}
	}
	return out
}

func (r *daRelaySetRecord) ensureMaps() {
	if r.chunks == nil {
		r.chunks = map[uint16]daRelayChunk{}
	}
}

// pruneChunksOutsideCommit drops every retained chunk the arriving commit places
// outside its declared range and reports them, so their exact claims are removed
// in the same owner hold that publishes the commit.
func (r *daRelaySetRecord) pruneChunksOutsideCommit() []daRelayMemberIdentity {
	var dropped []daRelayMemberIdentity
	for _, index := range sortedRetainedDAChunkIndexes(*r) {
		if index < r.commit.chunkCount {
			continue
		}
		dropped = append(dropped, r.chunks[index].daRelayMemberIdentity)
		delete(r.chunks, index)
	}
	return dropped
}

// dropAllChunks removes every retained chunk of a record and reports them in
// exact identity order. It is Section 5.2's commit-last mismatch effect: the
// first-seen commit stays, its chunks and their claims go.
func (r *daRelaySetRecord) dropAllChunks() []daRelayMemberIdentity {
	dropped := make([]daRelayMemberIdentity, 0, len(r.chunks))
	for _, index := range sortedRetainedDAChunkIndexes(*r) {
		dropped = append(dropped, r.chunks[index].daRelayMemberIdentity)
		delete(r.chunks, index)
	}
	r.payloadBytes = 0
	return dropped
}

// members lists one record's retained members in exact identity order: the
// commit first when the record holds one, then the chunks in strictly ascending
// index. Every removal, victim batch and claim-coverage walk uses this order, so
// none of them depends on map iteration order.
func (r daRelaySetRecord) members() []daRelayMemberIdentity {
	members := make([]daRelayMemberIdentity, 0, 1+len(r.chunks))
	if r.commit.chunkCount != 0 {
		members = append(members, r.commit.daRelayMemberIdentity)
	}
	for _, index := range sortedRetainedDAChunkIndexes(r) {
		members = append(members, r.chunks[index].daRelayMemberIdentity)
	}
	return members
}

// locators lists one record's txid -> member locator rows, in the same exact
// identity order as members.
func (r daRelaySetRecord) locators() map[[32]byte]daRelayLocator {
	rows := make(map[[32]byte]daRelayLocator, 1+len(r.chunks))
	if r.commit.chunkCount != 0 {
		rows[r.commit.txid] = daRelayLocator{daID: r.daID, kind: daRelayLocatorCommit}
	}
	for index, chunk := range r.chunks {
		rows[chunk.txid] = daRelayLocator{daID: r.daID, kind: daRelayLocatorChunk, chunkIndex: index}
	}
	return rows
}

// ownedByPeerQuota reports whether this member was admitted by a PEER whose
// quota identity is exactly key. It is deliberately NOT a raw peerQuotaKey
// comparison: a LOCAL or DETACHED_REORG member is peerless and carries the EMPTY
// quota key, so a string compare would make peer cleanup for "" select exactly
// the members RUBIN_COMPACT_BLOCKS.md Section 18.3 forbids it to touch.
func (m daRelayMemberIdentity) ownedByPeerQuota(key string) bool {
	return m.provenance.kind == daProvenancePeer && m.provenance.quotaIdentity == key
}

// peerCleanupPlan is Section 18.3's per-record peer-teardown selection for the
// peer quota identity key, over a record that is NOT a COMPLETE_SET (State C is
// not peer-quota state and this method is never reached for one).
//
// A commit is selected ONLY when it is itself PEER(key) AND every retained
// member of the record has PEER provenance — then the WHOLE staged record goes,
// PEER(other) members included, with every locator, charge and claim. If any
// LOCAL or DETACHED_REORG member exists the commit is INELIGIBLE and only the
// matching PEER(key) CHUNKS are removed, so an observable State B never
// downgrades to State A.
func (r daRelaySetRecord) peerCleanupPlan(key string) (daRelaySetRecord, []daRelayMemberIdentity, error) {
	if r.state == daRelayStateCompleteSet || r.wireBytes == 0 {
		return r, nil, nil
	}
	if r.commitEligibleForPeerCleanup(key) {
		return daRelaySetRecord{daID: r.daID}, r.members(), nil
	}
	out, removed := r.removePeerChunks(key)
	if len(removed) == 0 {
		return r, nil, nil
	}
	if out.emptyIncomplete() {
		return daRelaySetRecord{daID: r.daID}, removed, nil
	}
	if err := out.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, nil, err
	}
	return out, removed, nil
}

// removePeerChunks is peerCleanupPlan's chunk-selection scan: one state-mutation
// clone, from which every PEER(key) chunk is removed, reported in exact identity
// order.
func (r daRelaySetRecord) removePeerChunks(key string) (daRelaySetRecord, []daRelayMemberIdentity) {
	out := r.cloneForStateMutation()
	var removed []daRelayMemberIdentity
	for _, index := range sortedRetainedDAChunkIndexes(r) {
		chunk := r.chunks[index]
		if !chunk.ownedByPeerQuota(key) {
			continue
		}
		removed = append(removed, chunk.daRelayMemberIdentity)
		delete(out.chunks, index)
	}
	return out, removed
}

func (r daRelaySetRecord) commitEligibleForPeerCleanup(key string) bool {
	if r.commit.chunkCount == 0 || !r.commit.ownedByPeerQuota(key) {
		return false
	}
	for _, member := range r.members() {
		if member.provenance.kind != daProvenancePeer {
			return false
		}
	}
	return true
}

func (r daRelaySetRecord) emptyIncomplete() bool {
	return r.state != daRelayStateCompleteSet && r.commit.chunkCount == 0 && len(r.chunks) == 0
}

func (r daRelaySetRecord) validateChunkInsert(chunkIndex uint16) error {
	if _, exists := r.chunks[chunkIndex]; exists {
		return errDARelayDuplicateChunk
	}
	if r.commit.chunkCount != 0 && chunkIndex >= r.commit.chunkCount {
		return errDARelayChunkIndexOutsideCommit
	}
	return nil
}

func (r daRelaySetRecord) completionSnapshot() (daRelayCompletionSnapshot, bool) {
	if r.commit.chunkCount == 0 || r.state == daRelayStateCompleteSet || len(r.missingChunkIndexes()) != 0 {
		return daRelayCompletionSnapshot{}, false
	}
	snapshot := daRelayCompletionSnapshot{
		daID:                      r.daID,
		payloadCommitmentExpected: r.commit.payloadCommitment,
		chunkCount:                r.commit.chunkCount,
		chunks:                    make([]daRelayCompletionChunkSnapshot, 0, r.commit.chunkCount),
	}
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		chunk, ok := r.chunks[i]
		if !ok {
			return daRelayCompletionSnapshot{}, false
		}
		snapshot.chunks = append(snapshot.chunks, daRelayCompletionChunkSnapshot{
			chunkHash:  chunk.chunkHash,
			chunkIndex: i,
			payload:    chunk.payload,
		})
	}
	return snapshot, true
}

func (s daRelayCompletionSnapshot) payloadCommitment() (uint64, [32]byte) {
	hasher := sha3.New256()
	var payloadBytes uint64
	for _, chunk := range s.chunks {
		payloadBytes += uint64(len(chunk.payload))
		_, _ = hasher.Write(chunk.payload)
	}
	var payloadCommitment [32]byte
	copy(payloadCommitment[:], hasher.Sum(nil))
	return payloadBytes, payloadCommitment
}

// markComplete finalizes one record as State C. Completion clears ALL member
// provenance — State C is not peer-quota state and MUST NOT retain a member
// source (RUBIN_COMPACT_BLOCKS.md Section 18.3; the frozen D00-R3 authority
// pins state_c_member_provenance FORBIDDEN) — so no later cleanup, scoring or
// observation can attribute a completed member to the peer that happened to
// deliver it. The paired per-peer accounting keys are cleared with it: a
// State C record contributes no orphan accounting, and a cleared source with a
// live accounting key would be half a member identity.
func (r *daRelaySetRecord) markComplete(payloadBytes uint64) {
	r.payloadBytes = payloadBytes
	r.state = daRelayStateCompleteSet
	r.ttlBlocksRemaining = 0
	r.commit.provenance = DAProvenance{}
	r.commit.peerQuotaKey = ""
	for index, chunk := range r.chunks {
		chunk.payload = nil
		chunk.provenance = DAProvenance{}
		chunk.peerQuotaKey = ""
		r.chunks[index] = chunk
	}
}

func (r *daRelaySetRecord) recomputeOrphanTotals() error {
	r.wireBytes = retainedTxAccountingBytes(r.commit.wireBytes, r.commit.txBytes)
	for _, chunk := range r.chunks {
		var err error
		r.wireBytes, err = checkedAddUint64(r.wireBytes, retainedTxAccountingBytes(chunk.wireBytes, chunk.txBytes))
		if err != nil {
			return err
		}
	}
	return nil
}

// pinnedPayloadAccountingBytes reports what this record contributes to the
// DA_MEMPOOL_PINNED_PAYLOAD_MAX counter. RUBIN_COMPACT_BLOCKS §5.1 counts DA
// payload bytes only, so a retained COMPLETE_SET contributes exactly
// payloadBytes (the sum of its DA_CHUNK payload lengths, as recorded by
// markComplete) and every other state contributes zero. Commit metadata,
// retained transaction bytes and wire envelope overhead are never counted; a
// defensive zero-payload COMPLETE_SET therefore contributes zero as well.
func (r daRelaySetRecord) pinnedPayloadAccountingBytes() uint64 {
	if r.state != daRelayStateCompleteSet {
		return 0
	}
	return r.payloadBytes
}

func (r daRelaySetRecord) orphanAccounting() (daRelayRecordAccounting, error) {
	if r.hasNoOrphanAccounting() {
		return daRelayRecordAccounting{}, nil
	}
	accounting := daRelayRecordAccounting{peerBytes: map[string]uint64{}}
	if err := accounting.addCommit(r.commit); err != nil {
		return daRelayRecordAccounting{}, err
	}
	if err := accounting.addChunks(r.chunks); err != nil {
		return daRelayRecordAccounting{}, err
	}
	return accounting, nil
}

func (r daRelaySetRecord) hasNoOrphanAccounting() bool {
	return r.state == daRelayStateCompleteSet || (r.wireBytes == 0 && r.commit.wireBytes == 0 && len(r.commit.txBytes) == 0 && len(r.chunks) == 0)
}

func (a *daRelayRecordAccounting) addCommit(commit daRelayCommit) error {
	commitBytes := retainedTxAccountingBytes(commit.wireBytes, commit.txBytes)
	a.orphanBytes = commitBytes
	a.commitBytes = commitBytes
	return addPeerAccounting(a.peerBytes, commit.peerQuotaKey, commitBytes)
}

func (a *daRelayRecordAccounting) addChunks(chunks map[uint16]daRelayChunk) error {
	for _, chunk := range chunks {
		if err := a.addChunk(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (a *daRelayRecordAccounting) addChunk(chunk daRelayChunk) error {
	chunkBytes, err := orphanChunkAccountingBytes(chunk)
	if err != nil {
		return err
	}
	orphanBytes, err := checkedAddUint64(a.orphanBytes, chunkBytes)
	if err != nil {
		return err
	}
	a.orphanBytes = orphanBytes
	return addPeerAccounting(a.peerBytes, chunk.peerQuotaKey, chunkBytes)
}

func orphanChunkAccountingBytes(chunk daRelayChunk) (uint64, error) {
	chunkBytes := retainedTxAccountingBytes(chunk.wireBytes, chunk.txBytes)
	if len(chunk.txBytes) == 0 || len(chunk.payload) == 0 {
		return chunkBytes, nil
	}
	return checkedAddUint64(chunkBytes, uint64(len(chunk.payload)))
}

func retainedTxAccountingBytes(wireBytes uint64, txBytes []byte) uint64 {
	if len(txBytes) != 0 {
		return uint64(len(txBytes))
	}
	return wireBytes
}

// addPeerAccounting bills one member's bytes to its peer quota key. An EMPTY key
// is a PEERLESS member — LOCAL or DETACHED_REORG — and RUBIN_COMPACT_BLOCKS.md
// Section 5 gives those only the global and per-da_id caps, never a per-peer one,
// so it contributes to neither the map nor the per-peer cap.
func addPeerAccounting(peerBytes map[string]uint64, key string, bytes uint64) error {
	if bytes == 0 || key == "" {
		return nil
	}
	var err error
	peerBytes[key], err = checkedAddUint64(peerBytes[key], bytes)
	return err
}

func checkedApplyUint64DeltaCap(current, remove, add, limit uint64, capErr error) (uint64, error) {
	value, err := checkedApplyUint64Delta(current, remove, add)
	if err != nil {
		return 0, err
	}
	if value > limit {
		return 0, capErr
	}
	return value, nil
}

func checkedApplyUint64Delta(current uint64, remove uint64, add uint64) (uint64, error) {
	if current < remove {
		return 0, errDARelayArithmeticOverflow
	}
	return checkedAddUint64(current-remove, add)
}

func checkedAddUint64(a uint64, b uint64) (uint64, error) {
	if ^uint64(0)-a < b {
		return 0, errDARelayArithmeticOverflow
	}
	return a + b, nil
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	return append([]byte(nil), in...)
}
