package node

import (
	"bytes"
	"crypto/sha3"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// Completion capture requires an open, same-relay canonical DAAdmission and
// its continuously held ChainState guard. It neither acquires nor ends that guard.
// Tokens below are opaque identities; their live claims belong to the effect owner.
type daCompleteSnapshot struct {
	candidate daRelayAdmissionCandidate
	prior     daRelaySetRecord
	locators  map[[32]byte]daRelayLocator // target rows only
	mempool   *Mempool
	owner     *PendingOutpointOwner
	ttl       uint64
}

type daCompletePrepared struct {
	source *daCompleteSnapshot
	image  daRelayRecordImage
	pruned []DAAdmissionVictim
	set    daCompleteCapacitySet
}

type daCompleteMismatch struct {
	source  *daCompleteSnapshot
	image   daRelayRecordImage
	removed []DAAdmissionVictim
	kind    daRelayLocatorKind
}

type daCompletePreparation struct {
	duplicate *daRelayAdmissionOutcome
	prepared  *daCompletePrepared
	mismatch  *daCompleteMismatch
}

func (s *DARelayState) captureDACompleteSnapshot(candidate daRelayAdmissionCandidate) (*daCompleteSnapshot, daRelayAdmissionOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if duplicate, ok := s.duplicateDANonReplayLocked(candidate); ok {
		return nil, duplicate, nil
	}
	if s.sets == nil || s.locators == nil || s.mempool == nil || s.mempool.pendingOutpoints == nil {
		return nil, daRelayAdmissionOutcome{}, errDARelayImageIncompatible
	}
	snapshot, err := s.copyDACompleteSnapshotLocked(candidate)
	return snapshot, daRelayAdmissionOutcome{}, err
}

func (s *DARelayState) copyDACompleteSnapshotLocked(candidate daRelayAdmissionCandidate) (*daCompleteSnapshot, error) {
	prior, present := s.sets[candidate.member.locator.daID]
	if !present || prior.daID != candidate.member.locator.daID {
		return nil, errDARelayImageIncompatible
	}
	out := &daCompleteSnapshot{
		candidate: candidate, prior: prior.cloneOwnerReady(), mempool: s.mempool, owner: s.mempool.pendingOutpoints,
		locators: make(map[[32]byte]daRelayLocator, 1+len(prior.chunks)), ttl: s.caps.orphanTTLBlocks,
	}
	out.candidate.member.member = *candidate.member.member.clone()
	out.candidate.member.txBytes = cloneBytes(candidate.member.txBytes)
	out.candidate.member.payload = cloneBytes(candidate.member.payload)
	for _, row := range prior.locatorRows() {
		if _, duplicate := out.locators[row.txid]; duplicate || s.locators[row.txid] != row.locator {
			return nil, errDARelayImageIncompatible
		}
		out.locators[row.txid] = row.locator
	}
	return out, nil
}

// The caller passes the captured snapshot exclusively to this off-lock phase.
// Every error returns the zero result; mismatches never enter the resident phase.
func prepareDACompleteSnapshot(source *daCompleteSnapshot, duplicate daRelayAdmissionOutcome) (daCompletePreparation, error) {
	if duplicate.disposition == daRelayAdmissionDuplicate && source == nil {
		return daCompletePreparation{duplicate: &duplicate}, nil
	}
	if source == nil || duplicate != (daRelayAdmissionOutcome{}) {
		return daCompletePreparation{}, errDARelayImageIncompatible
	}
	image, pruned, err := source.stageCandidate()
	if err != nil {
		return daCompletePreparation{}, err
	}
	set, matches, err := parseDACompleteRecord(image.next)
	if err != nil {
		return daCompletePreparation{}, err
	}
	if !matches {
		return daCompletePreparation{mismatch: source.mismatch(image)}, nil
	}
	return source.prepareMatching(image, pruned, set)
}

func (source *daCompleteSnapshot) prepareMatching(image daRelayRecordImage, pruned []DAAdmissionVictim, set daCompleteCapacitySet) (daCompletePreparation, error) {
	image.next.markComplete(set.payloadBytes)
	if set.id != image.next.daID || set.totalBytes == 0 || set.payloadBytes != image.next.payloadBytes || set.receivedSequence != image.next.receivedTime {
		return daCompletePreparation{}, errDARelayImageIncompatible
	}
	image.next.completeIntrinsic = set
	return daCompletePreparation{prepared: &daCompletePrepared{source: source, image: image, pruned: pruned, set: set}}, nil
}

func (s *daCompleteSnapshot) stageCandidate() (daRelayRecordImage, []DAAdmissionVictim, error) {
	candidate := s.candidate
	if err := s.checkCandidateDomain(); err != nil {
		return daRelayRecordImage{}, nil, err
	}
	if err := s.prior.checkDANonReplayPrior(candidate.member.locator.daID, s.owner); err != nil {
		return daRelayRecordImage{}, nil, errDARelayImageIncompatible
	}
	if _, _, err := parseDACompleteMembers(s.prior); err != nil {
		return daRelayRecordImage{}, nil, err
	}
	image, pruned := stageDANonReplayCandidate(s.prior, true, candidate, s.ttl)
	if !image.next.completeByShape() {
		return daRelayRecordImage{}, nil, errDARelayImageIncompatible
	}
	if err := s.checkRetainedRecord(s.prior, make(map[[32]byte]bool), make(map[PendingOutpointToken]bool)); err != nil {
		return daRelayRecordImage{}, nil, err
	}
	return image, pruned, nil
}

func (s *daCompleteSnapshot) checkCandidateDomain() error {
	c := s.candidate
	if s.owner == nil || c.member.validate() != nil || c.member.member.token != (PendingOutpointToken{}) {
		return errDARelayImageIncompatible
	}
	return s.checkCandidateRole()
}

func (s *daCompleteSnapshot) checkCandidateRole() error {
	c := s.candidate
	type role struct {
		state            daRelaySetState
		count            uint16
		commitment, hash [32]byte
	}
	switch c.member.locator.kind {
	case daRelayLocatorCommit:
		if (role{state: s.prior.state, hash: c.chunkHash}) != (role{state: daRelayStateOrphanChunks}) {
			return errDARelayImageIncompatible
		}
	case daRelayLocatorChunk:
		if (role{state: s.prior.state, count: c.chunkCount, commitment: c.payloadCommitment}) != (role{state: daRelayStateStagedCommit}) {
			return errDARelayImageIncompatible
		}
		if c.member.locator.chunkIndex >= s.prior.commit.chunkCount || s.prior.completeByShape() {
			return errDARelayImageIncompatible
		}
	default:
		return errDARelayImageIncompatible
	}
	return nil
}

func parseDACompleteMember(raw []byte, identity *daRelayMemberIdentity) (canonicalRetainedDAMember, error) {
	if identity.validate() != nil || checkOwnerReadyRetainedBytes(raw) != nil {
		return canonicalRetainedDAMember{}, errDARelayImageIncompatible
	}
	member, err := parseRetainedDAMember(raw, "completion")
	if err != nil {
		return canonicalRetainedDAMember{}, errDARelayImageIncompatible
	}
	if member.ids.TxID != identity.txid || member.ids.WTxID != identity.wtxid || !slices.Equal(relayMetadataInputs(member.tx), identity.inputs) {
		return canonicalRetainedDAMember{}, errDARelayImageIncompatible
	}
	return member, nil
}

func parseDACompleteRecord(record daRelaySetRecord) (daCompleteCapacitySet, bool, error) {
	indexes, payloads, err := parseDACompleteMembers(record)
	if err != nil {
		return daCompleteCapacitySet{}, false, err
	}
	return sumDACompleteRecord(record, indexes, payloads)
}

// Bind every member before sums; pruned prior members contribute no completing fee.
func parseDACompleteMembers(record daRelaySetRecord) ([]uint16, [][]byte, error) {
	if record.commit.member != nil {
		if err := parseDACompleteCommit(record); err != nil {
			return nil, nil, err
		}
	}
	indexes := sortedRetainedDAChunkIndexes(record)
	payloads := make([][]byte, len(indexes))
	for i, index := range indexes {
		payload, err := parseDACompleteChunk(record, index)
		if err != nil {
			return nil, nil, err
		}
		payloads[i] = payload
	}
	return indexes, payloads, nil
}

func sumDACompleteRecord(record daRelaySetRecord, indexes []uint16, payloads [][]byte) (daCompleteCapacitySet, bool, error) {
	set := daCompleteCapacitySet{id: record.daID, receivedSequence: record.receivedTime}
	if record.commit.member != nil {
		if err := addDACompleteMember(&set, record.commit.member, record.commit.txBytes, nil); err != nil {
			return daCompleteCapacitySet{}, false, err
		}
	}
	for i, index := range indexes {
		chunk := record.chunks[index]
		if err := addDACompleteMember(&set, chunk.member, chunk.txBytes, payloads[i]); err != nil {
			return daCompleteCapacitySet{}, false, err
		}
	}
	hash := sha3.New256()
	for _, payload := range payloads {
		_, _ = hash.Write(payload)
	}
	return set, bytes.Equal(hash.Sum(nil), record.commit.payloadCommitment[:]), nil
}

func parseDACompleteCommit(record daRelaySetRecord) error {
	member, err := parseDACompleteMember(record.commit.txBytes, record.commit.member)
	if err != nil {
		return err
	}
	if record.commit.chunkCount == 0 || uint64(record.commit.chunkCount) > consensus.MAX_DA_CHUNK_COUNT || checkRetainedDACommitRole(member.tx, record) != nil {
		return errDARelayImageIncompatible
	}
	commitment, err := daAdmissionPayloadCommitment(member.tx)
	if err != nil || commitment != record.commit.payloadCommitment {
		return errDARelayImageIncompatible
	}
	return nil
}

func parseDACompleteChunk(record daRelaySetRecord, index uint16) ([]byte, error) {
	chunk := record.chunks[index]
	member, err := parseDACompleteMember(chunk.txBytes, chunk.member)
	if err != nil {
		return nil, err
	}
	if checkRetainedDAChunkRole(member.tx, record.daID, index) != nil || checkOwnerReadyPayload(member.tx.DaPayload) != nil {
		return nil, errDARelayImageIncompatible
	}
	type binding struct {
		index    uint16
		id, hash [32]byte
	}
	if (binding{chunk.chunkIndex, chunk.daID, chunk.chunkHash}) != (binding{index, record.daID, member.tx.DaChunkCore.ChunkHash}) || sha3.Sum256(member.tx.DaPayload) != chunk.chunkHash {
		return nil, errDARelayImageIncompatible
	}
	return bindDACompletePayload(record.state, chunk.payload, member.tx.DaPayload)
}

func bindDACompletePayload(state daRelaySetState, cached, parsed []byte) ([]byte, error) {
	if state == daRelayStateCompleteSet {
		if cached != nil {
			return nil, errDARelayImageIncompatible
		}
	} else if !bytes.Equal(cached, parsed) {
		return nil, errDARelayImageIncompatible
	}
	return parsed, nil
}

func addDACompleteMember(set *daCompleteCapacitySet, member *daRelayMemberIdentity, raw, payload []byte) error {
	fee, ok := set.fee.CheckedAdd(member.fee)
	if !ok {
		return errDARelayArithmeticOverflow
	}
	var err error
	set.totalBytes, err = checkedAddUint64(set.totalBytes, uint64(len(raw)))
	if err != nil {
		return err
	}
	set.payloadBytes, err = checkedAddUint64(set.payloadBytes, uint64(len(payload)))
	set.fee = fee
	return err
}

func (s *daCompleteSnapshot) mismatch(image daRelayRecordImage) *daCompleteMismatch {
	out := &daCompleteMismatch{source: s, image: image, kind: s.candidate.member.locator.kind}
	if out.kind == daRelayLocatorChunk {
		out.image.next = s.prior.cloneOwnerReady()
		return out
	}
	for _, index := range sortedRetainedDAChunkIndexes(s.prior) {
		member := s.prior.chunks[index].member
		out.removed = append(out.removed, DAAdmissionVictim{TxID: member.txid, Token: member.token, Inputs: slices.Clone(member.inputs)})
	}
	out.image.next.chunks = make(map[uint16]daRelayChunk)
	return out
}

// capacityInput reads only current scalar metadata while the final DA lock is held.
type daCompleteLiveTotals struct {
	staged, commitBytes, completeBytes, payload uint64
}

func (s *DARelayState) capacityInput(source *daCompleteSnapshot, candidate daCompleteCapacitySet) (daCompleteCapacityInput, error) {
	in := daCompleteCapacityInput{
		byteCap: s.caps.stagedBytes, stagedBytes: s.stagedBytes,
		completeBytes: s.completeBytes, completeCount: s.completeCount,
		completePayload: s.pinnedPayloadBytes, candidate: candidate,
	}
	accounting, err := source.prior.ownerReadyAccounting()
	if err != nil {
		return daCompleteCapacityInput{}, err
	}
	in.priorCredit = accounting.stagedBytes
	txids, tokens := make(map[[32]byte]bool), make(map[PendingOutpointToken]bool)
	if err := source.checkRetainedRecord(source.prior, txids, tokens); err != nil {
		return daCompleteCapacityInput{}, err
	}
	totals := daCompleteLiveTotals{}
	if err := s.scanDACompleteLive(&in, source.owner, txids, tokens, &totals); err != nil {
		return daCompleteCapacityInput{}, err
	}
	if totals != (daCompleteLiveTotals{s.stagedBytes, s.orphanCommitOverheadBytes, s.completeBytes, s.pinnedPayloadBytes}) || uint64(len(in.residents)) != s.completeCount {
		return daCompleteCapacityInput{}, errDARelayImageIncompatible
	}
	if err := s.checkLiveCompleteLocators(source, txids); err != nil {
		return daCompleteCapacityInput{}, err
	}
	return in, nil
}

func (s *DARelayState) scanDACompleteLive(in *daCompleteCapacityInput, owner *PendingOutpointOwner, txids map[[32]byte]bool, tokens map[PendingOutpointToken]bool, totals *daCompleteLiveTotals) error {
	for id, record := range s.sets {
		if id != record.daID {
			return errDARelayImageIncompatible
		}
		switch record.state {
		case daRelayStateOrphanChunks:
			// State A is outside the shared bound.
		case daRelayStateStagedCommit:
			if err := totals.addB(record); err != nil {
				return err
			}
		case daRelayStateCompleteSet:
			if err := s.addLiveC(in, record, owner, txids, tokens, totals); err != nil {
				return err
			}
		default:
			return errDARelayImageIncompatible
		}
	}
	return nil
}

func (totals *daCompleteLiveTotals) addB(record daRelaySetRecord) error {
	charge, err := record.ownerReadyAccounting()
	if err != nil {
		return errDARelayImageIncompatible
	}
	totals.staged, err = checkedAddUint64(totals.staged, charge.stagedBytes)
	if err != nil {
		return errDARelayImageIncompatible
	}
	totals.commitBytes, err = checkedAddUint64(totals.commitBytes, charge.commitBytes)
	if err != nil {
		return errDARelayImageIncompatible
	}
	return nil
}

func (s *DARelayState) addLiveC(in *daCompleteCapacityInput, record daRelaySetRecord, owner *PendingOutpointOwner, txids map[[32]byte]bool, tokens map[PendingOutpointToken]bool, totals *daCompleteLiveTotals) error {
	set, err := s.prepareResident(record, owner, txids, tokens)
	if err != nil {
		return err
	}
	in.residents = append(in.residents, set)
	totals.completeBytes, err = checkedAddUint64(totals.completeBytes, set.totalBytes)
	if err != nil {
		return errDARelayImageIncompatible
	}
	totals.payload, err = checkedAddUint64(totals.payload, set.payloadBytes)
	if err != nil {
		return errDARelayImageIncompatible
	}
	return nil
}

func (s *DARelayState) checkLiveCompleteLocators(source *daCompleteSnapshot, txids map[[32]byte]bool) error {
	for txid, locator := range s.locators {
		record, present := s.sets[locator.daID]
		if !present {
			return errDARelayImageIncompatible
		}
		if locator.daID == source.prior.daID || record.state == daRelayStateCompleteSet {
			if !txids[txid] {
				return errDARelayImageIncompatible
			}
		}
	}
	return nil
}

func (s *DARelayState) prepareResident(record daRelaySetRecord, owner *PendingOutpointOwner, txids map[[32]byte]bool, tokens map[PendingOutpointToken]bool) (daCompleteCapacitySet, error) {
	set := daCompleteCapacitySet{id: record.daID, receivedSequence: record.receivedTime, payloadBytes: record.payloadBytes}
	if s.checkResidentShape(record, set.payloadBytes) != nil {
		return daCompleteCapacitySet{}, errDARelayImageIncompatible
	}
	for _, row := range record.locatorRows() {
		member, raw := record.commit.member, record.commit.txBytes
		if row.locator.kind == daRelayLocatorChunk {
			chunk := record.chunks[row.locator.chunkIndex]
			member, raw = chunk.member, chunk.txBytes
		}
		if s.checkDACompleteLiveMember(row, member, raw, owner, txids, tokens) != nil {
			return daCompleteCapacitySet{}, errDARelayImageIncompatible
		}
		if err := addDACompleteMember(&set, member, raw, nil); err != nil {
			return daCompleteCapacitySet{}, errDARelayImageIncompatible
		}
		txids[row.txid], tokens[member.token] = true, true
	}
	type bounds struct {
		intrinsic                         daCompleteCapacitySet
		nonzero, withinCap, payloadWithin bool
	}
	if (bounds{record.completeIntrinsic, set.totalBytes != 0, set.totalBytes <= s.caps.stagedBytes, set.payloadBytes <= set.totalBytes}) != (bounds{set, true, true, true}) {
		return daCompleteCapacitySet{}, errDARelayImageIncompatible
	}
	return set, nil
}

func (s *DARelayState) checkDACompleteLiveMember(row daRelayLocatorRow, member *daRelayMemberIdentity, raw []byte, owner *PendingOutpointOwner, txids map[[32]byte]bool, tokens map[PendingOutpointToken]bool) error {
	if member == nil || member.validate() != nil {
		return errDARelayImageIncompatible
	}
	type binding struct {
		owner                             *PendingOutpointOwner
		nonzero, freshTx, freshToken, raw bool
		locator                           daRelayLocator
	}
	if (binding{member.token.owner, member.token.seq != 0, !txids[row.txid], !tokens[member.token], len(raw) != 0, s.locators[row.txid]}) != (binding{owner, true, true, true, true, row.locator}) {
		return errDARelayImageIncompatible
	}
	return nil
}

func (s *DARelayState) checkResidentShape(record daRelaySetRecord, payload uint64) error {
	type header struct {
		state                                                                                         daRelaySetState
		commit, chunks, raw, count, countWithin, revision, revisionCurrent, received, receivedCurrent bool
	}
	if (header{record.state, record.commit.member != nil, len(record.chunks) == int(record.commit.chunkCount), len(record.commit.txBytes) != 0, record.commit.chunkCount != 0, uint64(record.commit.chunkCount) <= consensus.MAX_DA_CHUNK_COUNT, record.revision != 0, record.revision <= s.records, record.receivedTime != 0, record.receivedTime <= s.nextReceivedTime}) != (header{daRelayStateCompleteSet, true, true, true, true, true, true, true, true, true}) {
		return errDARelayImageIncompatible
	}
	type chunkShape struct {
		member          bool
		index           uint16
		id              [32]byte
		raw, payloadNil bool
	}
	for index, chunk := range record.chunks {
		if (chunkShape{chunk.member != nil, chunk.chunkIndex, chunk.daID, len(chunk.txBytes) != 0, chunk.payload == nil}) != (chunkShape{true, index, record.daID, true, true}) {
			return errDARelayImageIncompatible
		}
	}
	return checkDACompleteResidues(record, payload)
}

func checkDACompleteResidues(record daRelaySetRecord, payload uint64) error {
	type residues struct {
		payload, ttl, wire uint64
		replaceable        bool
	}
	if (residues{record.payloadBytes, record.ttlBlocksRemaining, record.wireBytes, record.replaceableChunks != nil}) != (residues{payload: payload}) {
		return errDARelayImageIncompatible
	}
	type commitShape struct {
		id    [32]byte
		wire  uint64
		quota string
	}
	if (commitShape{record.commit.daID, record.commit.wireBytes, record.commit.peerQuotaKey}) != (commitShape{id: record.daID}) {
		return errDARelayImageIncompatible
	}
	type chunkResidue struct {
		wire    uint64
		quota   string
		checked bool
	}
	for _, chunk := range record.chunks {
		if (chunkResidue{chunk.wireBytes, chunk.peerQuotaKey, chunk.hashChecked}) != (chunkResidue{}) || chunk.chunkIndex >= record.commit.chunkCount {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

func (s *daCompleteSnapshot) checkRetainedRecord(record daRelaySetRecord, txids map[[32]byte]bool, tokens map[PendingOutpointToken]bool) error {
	for _, row := range record.locatorRows() {
		member := record.commit.member
		if row.locator.kind == daRelayLocatorChunk {
			member = record.chunks[row.locator.chunkIndex].member
		}
		if err := s.checkRetainedIdentity(row, member, txids, tokens); err != nil {
			return err
		}
	}
	return nil
}

func (s *daCompleteSnapshot) checkRetainedIdentity(row daRelayLocatorRow, member *daRelayMemberIdentity, txids map[[32]byte]bool, tokens map[PendingOutpointToken]bool) error {
	if txids[row.txid] || tokens[member.token] || row.txid == s.candidate.member.member.txid {
		return errDARelayImageIncompatible
	}
	if member.token.owner != s.owner || member.token.seq == 0 {
		return errDARelayImageIncompatible
	}
	if locator, ok := s.locators[row.txid]; !ok || locator != row.locator {
		return errDARelayImageIncompatible
	}
	txids[row.txid], tokens[member.token] = true, true
	return nil
}
