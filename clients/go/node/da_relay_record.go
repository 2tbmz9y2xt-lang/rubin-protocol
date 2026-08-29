package node

import (
	"bytes"
	"crypto/sha3"
	"maps"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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

func (s *DARelayState) nextMonotonicReceivedTime() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	receivedTime, err := s.nextReceivedTimeLocked()
	if err != nil {
		return 0, err
	}
	s.nextReceivedTime = receivedTime
	return receivedTime, nil
}

func (s *DARelayState) nextReceivedTimeLocked() (uint64, error) {
	return checkedAddUint64(s.nextReceivedTime, 1)
}

func (s *DARelayState) assignFirstSeenReceivedTimeLocked(record *daRelaySetRecord) error {
	if record.receivedTime != 0 {
		return nil
	}
	receivedTime, err := s.nextReceivedTimeLocked()
	if err != nil {
		return err
	}
	record.receivedTime = receivedTime
	return nil
}

func (r daRelaySetRecord) missingChunkIndexes() []uint16 {
	if r.commit.chunkCount == 0 || r.state == daRelayStateCompleteSet {
		return nil
	}
	var missing []uint16
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		_, ok := r.chunks[i]
		if !ok || r.replaceableChunks[i] {
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
	if r.replaceableChunks != nil {
		out.replaceableChunks = make(map[uint16]bool, len(r.replaceableChunks))
		for index, replaceable := range r.replaceableChunks {
			out.replaceableChunks[index] = replaceable
		}
	}
	return out
}

func (r *daRelaySetRecord) ensureMaps() {
	if r.chunks == nil {
		r.chunks = map[uint16]daRelayChunk{}
	}
}

func (r *daRelaySetRecord) pruneChunksOutsideCommit() {
	for index := range r.chunks {
		if index >= r.commit.chunkCount {
			delete(r.chunks, index)
			delete(r.replaceableChunks, index)
		}
	}
}

func (r daRelaySetRecord) withoutPeerQuotaKey(key string) (daRelaySetRecord, bool, error) {
	if r.state == daRelayStateCompleteSet || r.wireBytes == 0 {
		return r, false, nil
	}

	out := r.cloneForStateMutation()
	changed := out.dropCommitForPeerQuotaKey(key)
	if out.dropChunksForPeerQuotaKey(key) {
		changed = true
	}
	if !changed {
		return r, false, nil
	}
	out.payloadBytes = 0
	if out.commit.chunkCount == 0 {
		out.state = daRelayStateOrphanChunks
		out.replaceableChunks = nil
	}
	if out.emptyIncomplete() {
		out.wireBytes = 0
		return out, true, nil
	}
	if err := out.recomputeOrphanTotals(); err != nil {
		return daRelaySetRecord{}, false, err
	}
	return out, true, nil
}

func (r *daRelaySetRecord) dropCommitForPeerQuotaKey(key string) bool {
	if r.commit.wireBytes == 0 || r.commit.peerQuotaKey != key {
		return false
	}
	r.commit = daRelayCommit{}
	r.replaceableChunks = nil
	return true
}

func (r *daRelaySetRecord) dropChunksForPeerQuotaKey(key string) bool {
	changed := false
	for index, chunk := range r.chunks {
		if chunk.wireBytes == 0 || chunk.peerQuotaKey != key {
			continue
		}
		delete(r.chunks, index)
		delete(r.replaceableChunks, index)
		changed = true
	}
	return changed
}

func (r daRelaySetRecord) emptyIncomplete() bool {
	return r.state != daRelayStateCompleteSet && r.commit.chunkCount == 0 && len(r.chunks) == 0
}

func (r daRelaySetRecord) validateChunkInsert(chunkIndex uint16) error {
	if _, exists := r.chunks[chunkIndex]; exists {
		if r.replaceableChunks[chunkIndex] {
			return nil
		}
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

func (r daRelaySetRecord) completeByShape() bool {
	_, complete := r.completionSnapshot()
	return complete
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

func (s *DARelayState) stageCommitDroppingMatchingCompletionChunks(peerQuotaKey string, commit daRelayCommit, txBytesOwned bool, snapshot daRelayCompletionSnapshot) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, commitTxBytesOwned, err := s.stageDACommitRecordLocked(peerQuotaKey, commit, txBytesOwned)
	if err != nil {
		return false, err
	}
	if !snapshot.matchesRecord(record) {
		return false, nil
	}
	indexesToDrop, ok := record.matchingCompletionChunkIndexes(snapshot)
	if !ok {
		return false, nil
	}
	record.dropChunks(indexesToDrop)
	record.payloadBytes = 0
	record.state = daRelayStateStagedCommit
	if err := record.recomputeOrphanTotals(); err != nil {
		return false, err
	}
	if !commitTxBytesOwned {
		if err := s.checkDASetRecordCapsLocked(record); err != nil {
			return false, err
		}
		record.cloneRetainedTxBytes()
	}
	if err := s.applyDASetRecordLocked(record); err != nil {
		return false, err
	}
	return true, nil
}

func (s *DARelayState) markMatchingCompletionChunksReplaceable(snapshot daRelayCompletionSnapshot) (retry bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.sets[snapshot.daID].cloneForStateMutation()
	if record.state == daRelayStateCompleteSet || record.commit.chunkCount != snapshot.chunkCount || record.commit.payloadCommitment != snapshot.payloadCommitmentExpected {
		return true, nil
	}
	indexes, ok := record.matchingCompletionChunkIndexes(snapshot)
	if !ok {
		return false, nil
	}
	if len(indexes) != len(snapshot.chunks) {
		return false, nil
	}
	record.markChunksReplaceable(indexes)
	if err := s.applyDASetRecordLocked(record); err != nil {
		return false, err
	}
	return false, nil
}

func (r daRelaySetRecord) matchingCompletionChunkIndexes(snapshot daRelayCompletionSnapshot) ([]uint16, bool) {
	indexes := make([]uint16, 0, len(snapshot.chunks))
	for _, snapshotChunk := range snapshot.chunks {
		chunk, ok := r.chunks[snapshotChunk.chunkIndex]
		if !ok {
			continue
		}
		if chunk.chunkHash != snapshotChunk.chunkHash || len(chunk.payload) != len(snapshotChunk.payload) {
			return nil, false
		}
		indexes = append(indexes, snapshotChunk.chunkIndex)
	}
	return indexes, true
}

func (r *daRelaySetRecord) dropChunks(indexes []uint16) {
	for _, index := range indexes {
		delete(r.chunks, index)
		delete(r.replaceableChunks, index)
	}
}

func (r *daRelaySetRecord) markChunksReplaceable(indexes []uint16) {
	if r.replaceableChunks == nil {
		r.replaceableChunks = map[uint16]bool{}
	}
	for _, index := range indexes {
		r.replaceableChunks[index] = true
	}
}

func (s daRelayCompletionSnapshot) matchesRecord(r daRelaySetRecord) bool {
	current, ok := r.completionSnapshot()
	if !ok {
		return false
	}
	return s.matchesHeader(current) && completionChunksMatch(s.chunks, current.chunks)
}

func (s daRelayCompletionSnapshot) matchesHeader(current daRelayCompletionSnapshot) bool {
	return current.daID == s.daID &&
		current.payloadCommitmentExpected == s.payloadCommitmentExpected &&
		current.chunkCount == s.chunkCount
}

func completionChunksMatch(expected, current []daRelayCompletionChunkSnapshot) bool {
	if len(current) != len(expected) {
		return false
	}
	for i := range expected {
		if !completionChunkMatches(expected[i], current[i]) {
			return false
		}
	}
	return true
}

func completionChunkMatches(expected, current daRelayCompletionChunkSnapshot) bool {
	return current.chunkIndex == expected.chunkIndex &&
		current.chunkHash == expected.chunkHash &&
		len(current.payload) == len(expected.payload)
}

func (r *daRelaySetRecord) markComplete(payloadBytes uint64) {
	r.payloadBytes = payloadBytes
	r.state = daRelayStateCompleteSet
	r.ttlBlocksRemaining = 0
	r.replaceableChunks = nil
	for index, chunk := range r.chunks {
		chunk.payload = nil
		r.chunks[index] = chunk
	}
}

func (r *daRelaySetRecord) cloneRetainedTxBytes() {
	if len(r.commit.txBytes) != 0 {
		r.commit.txBytes = cloneBytes(r.commit.txBytes)
	}
	for index, chunk := range r.chunks {
		if len(chunk.txBytes) == 0 {
			continue
		}
		chunk.txBytes = cloneBytes(chunk.txBytes)
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

func addPeerAccounting(peerBytes map[string]uint64, key string, bytes uint64) error {
	if bytes == 0 {
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

// daRelayRecordImage is ONE record transition staged as a PURE function of a
// caller-owned pre-state: building one mutates nothing and two images staged from
// one pre-state share nothing. baseline and present are CALLER observations the
// projector rechecks against live state.
type daRelayRecordImage struct {
	daID     [32]byte
	present  bool
	baseline uint64
	member   daRelayOwnerReadyMember
	next     daRelaySetRecord
	remove   bool
}

// stageDAOwnerReadyMember is total; an unusable member simply stages a record the
// projector then refuses. A NON-RESIDENT staging deliberately ignores the
// pre-state and starts from the zero record, so a projection over an absent record
// can only ever install the single candidate member.
func stageDAOwnerReadyMember(pre daRelaySetRecord, present bool, member daRelayOwnerReadyMember) daRelayRecordImage {
	image := daRelayRecordImage{daID: member.locator.daID, present: present, member: member}
	if present {
		image.baseline = pre.revision
		image.next = pre.cloneOwnerReady()
	} else {
		image.next.daID = member.locator.daID
	}
	switch member.locator.kind {
	case daRelayLocatorCommit:
		image.next.commit.daID = image.next.daID
		image.next.commit.member = member.member.clone()
		image.next.commit.txBytes = cloneBytes(member.txBytes)
	case daRelayLocatorChunk:
		if image.next.chunks == nil {
			image.next.chunks = map[uint16]daRelayChunk{}
		}
		chunk := image.next.chunks[member.locator.chunkIndex]
		chunk.daID = image.next.daID
		chunk.chunkIndex = member.locator.chunkIndex
		chunk.member = member.member.clone()
		chunk.txBytes = cloneBytes(member.txBytes)
		chunk.payload = cloneBytes(member.payload)
		image.next.chunks[member.locator.chunkIndex] = chunk
	}
	return image
}

func stageDAOwnerReadyRemoval(pre daRelaySetRecord, present bool) daRelayRecordImage {
	return daRelayRecordImage{daID: pre.daID, present: present, baseline: pre.revision, remove: true}
}

// cloneOwnerReady shares NOTHING mutable with r. cloneWithPayloads is not reused:
// it keeps the caller's retained bytes shared at one setting and drops them at
// the other; this kernel needs a record owning all of its bytes.
func (r daRelaySetRecord) cloneOwnerReady() daRelaySetRecord {
	out := r
	out.commit.txBytes = cloneBytes(r.commit.txBytes)
	out.commit.member = r.commit.member.clone()
	if r.chunks != nil {
		out.chunks = make(map[uint16]daRelayChunk, len(r.chunks))
		for index, chunk := range r.chunks {
			chunk.txBytes = cloneBytes(chunk.txBytes)
			chunk.payload = cloneBytes(chunk.payload)
			chunk.member = chunk.member.clone()
			out.chunks[index] = chunk
		}
	}
	out.replaceableChunks = maps.Clone(r.replaceableChunks)
	return out
}

func (m daRelayMemberIdentity) clone() daRelayMemberIdentity {
	if len(m.inputs) != 0 {
		m.inputs = append([]consensus.Outpoint(nil), m.inputs...)
	}
	return m
}

// locatorRows emits a FIXED order — commit first, then chunks ascending — one row
// per occupied slot, so len(rows) is also the member count. No walk here can
// produce a zero-txid row: validateOwnerReady refuses a resident record holding an
// entry without an identity, and staging starts from the zero record.
func (r daRelaySetRecord) locatorRows() []daRelayLocatorRow {
	rows := make([]daRelayLocatorRow, 0, 1+len(r.chunks))
	if r.commit.member.txid != ([32]byte{}) {
		rows = append(rows, daRelayLocatorRow{
			txid:    r.commit.member.txid,
			locator: daRelayLocator{daID: r.daID, kind: daRelayLocatorCommit},
		})
	}
	for _, index := range sortedRetainedDAChunkIndexes(r) {
		rows = append(rows, daRelayLocatorRow{
			txid:    r.chunks[index].member.txid,
			locator: daRelayLocator{daID: r.daID, kind: daRelayLocatorChunk, chunkIndex: index},
		})
	}
	return rows
}

// ownerReadyAccounting derives RUBIN_COMPACT_BLOCKS.md Section 18.1's
// incomplete_member_charge and total_fee(da_id). The legacy wireBytes fallback
// of retainedTxAccountingBytes has no place here: an owner-ready member always
// carries its retained bytes.
//
// The per-peer key comes from the member's own provenance and from nothing else
// — never from the cached peerQuotaKey field, which belongs to the legacy path.
// A peerless member derives the empty key and is charged under it: "" is a
// shared bucket sharing the per-peer cap, and whether Section 18.1's State B
// exemption should eventually separate that bucket is a live-path question this
// kernel does not own. The walk is over sorted chunk indexes, so neither the
// result nor the identity of a refusal depends on Go map iteration order.
func (r daRelaySetRecord) ownerReadyAccounting() (daRelayRecordAccounting, consensus.Uint128, error) {
	accounting := daRelayRecordAccounting{peerBytes: map[string]uint64{}}
	var totalFee consensus.Uint128
	var err error
	if r.commit.member.txid != ([32]byte{}) {
		accounting.commitBytes = uint64(len(r.commit.txBytes))
		if totalFee, err = accounting.addOwnerReadyMember(r.commit.member, accounting.commitBytes, totalFee); err != nil {
			return daRelayRecordAccounting{}, consensus.Uint128{}, err
		}
	}
	for _, index := range sortedRetainedDAChunkIndexes(r) {
		chunk := r.chunks[index]
		charge, chargeErr := checkedAddUint64(uint64(len(chunk.txBytes)), uint64(len(chunk.payload)))
		if chargeErr != nil {
			return daRelayRecordAccounting{}, consensus.Uint128{}, chargeErr
		}
		if totalFee, err = accounting.addOwnerReadyMember(chunk.member, charge, totalFee); err != nil {
			return daRelayRecordAccounting{}, consensus.Uint128{}, err
		}
	}
	return accounting, totalFee, nil
}

func (a *daRelayRecordAccounting) addOwnerReadyMember(member daRelayMemberIdentity, charge uint64, totalFee consensus.Uint128) (consensus.Uint128, error) {
	orphanBytes, err := checkedAddUint64(a.orphanBytes, charge)
	if err != nil {
		return consensus.Uint128{}, err
	}
	a.orphanBytes = orphanBytes
	if err := addPeerAccounting(a.peerBytes, member.provenance.quotaKey(), charge); err != nil {
		return consensus.Uint128{}, err
	}
	fee, ok := totalFee.CheckedAdd(member.fee)
	if !ok {
		return consensus.Uint128{}, errDARelayArithmeticOverflow
	}
	return fee, nil
}
