package node

import (
	"bytes"
	"crypto/sha3"
	"math"
	"slices"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// This dormant producer requires an open, same-relay canonical DAAdmission and
// its continuously held ChainState guard. It neither acquires nor ends that guard.
// Tokens below are opaque identities; their live claims belong to the effect owner.
type daCompleteSnapshot struct {
	publicationBase                *DARelayState
	candidate                      daRelayAdmissionCandidate
	prior                          daRelaySetRecord
	residents                      []daRelaySetRecord
	locators                       map[[32]byte]daRelayLocator
	owner                          *PendingOutpointOwner
	input                          daCompleteCapacityInput
	records, nextReceivedTime, ttl uint64
}

type daCompletePrepared struct {
	source *daCompleteSnapshot
	image  daRelayRecordImage
	pruned []DAAdmissionVictim
	input  daCompleteCapacityInput
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
	count := 0
	for _, record := range s.sets {
		if record.state == daRelayStateCompleteSet {
			count++
		}
	}
	if count > 65536 {
		return nil, errDARelayImageIncompatible
	}
	prior, present := s.sets[candidate.member.locator.daID]
	if !present || prior.daID != candidate.member.locator.daID {
		return nil, errDARelayImageIncompatible
	}
	out := &daCompleteSnapshot{
		candidate: candidate, prior: prior.cloneOwnerReady(), owner: s.mempool.pendingOutpoints,
		residents: make([]daRelaySetRecord, 0, count), locators: make(map[[32]byte]daRelayLocator),
		input: daCompleteCapacityInput{
			byteCap: s.caps.stagedBytes, stagedBytes: s.stagedBytes,
			completeBytes: s.completeBytes, completeCount: s.completeCount, completePayload: s.pinnedPayloadBytes,
		},
		records: s.records, nextReceivedTime: s.nextReceivedTime, ttl: s.caps.orphanTTLBlocks,
	}
	out.candidate.member.member = *candidate.member.member.clone()
	out.candidate.member.txBytes = cloneBytes(candidate.member.txBytes)
	out.candidate.member.payload = cloneBytes(candidate.member.payload)
	if err := out.copyResidents(s); err != nil {
		return nil, err
	}
	out.publicationBase = s.cloneForAtomicBatchLocked()
	out.publicationBase.sets[out.prior.daID] = out.prior
	for _, record := range out.residents {
		out.publicationBase.sets[record.daID] = record
	}
	return out, nil
}

func (out *daCompleteSnapshot) copyResidents(s *DARelayState) error {
	ids := make(map[[32]byte]bool, cap(out.residents)+1)
	for id, record := range s.sets {
		if record.state != daRelayStateCompleteSet {
			continue
		}
		if id != record.daID {
			return errDARelayImageIncompatible
		}
		copied := record.cloneOwnerReady()
		for index, chunk := range record.chunks {
			if len(chunk.payload) == 0 {
				retained := copied.chunks[index]
				retained.payload = slices.Clone(chunk.payload)
				copied.chunks[index] = retained
			}
		}
		out.residents = append(out.residents, copied)
		ids[id] = true
	}
	ids[out.candidate.member.locator.daID] = true
	for txid, locator := range s.locators {
		if ids[locator.daID] {
			out.locators[txid] = locator
		}
	}
	return out.checkCapturedLocators()
}

func (s *daCompleteSnapshot) checkCapturedLocators() error {
	expected := make(map[[32]byte]daRelayLocator)
	for _, record := range append([]daRelaySetRecord{s.prior}, s.residents...) {
		for _, row := range record.locatorRows() {
			if _, present := expected[row.txid]; present {
				return errDARelayImageIncompatible
			}
			expected[row.txid] = row.locator
			if locator, present := s.locators[row.txid]; !present || locator != row.locator {
				return errDARelayImageIncompatible
			}
		}
	}
	if len(expected) != len(s.locators) {
		return errDARelayImageIncompatible
	}
	return nil
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
	if source.nextReceivedTime == math.MaxUint64 {
		return daCompletePreparation{}, errDARelayArithmeticOverflow
	}
	input, err := source.capacityInput(set)
	if err != nil {
		return daCompletePreparation{}, err
	}
	image.next.markComplete(set.payloadBytes)
	if set.id != image.next.daID || set.totalBytes == 0 || set.payloadBytes != image.next.payloadBytes || set.receivedSequence != image.next.receivedTime {
		return daCompletePreparation{}, errDARelayImageIncompatible
	}
	image.next.completeIntrinsic = set
	return daCompletePreparation{prepared: &daCompletePrepared{source: source, image: image, pruned: pruned, input: input}}, nil
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
	if s.prior.receivedTime > s.nextReceivedTime || s.prior.revision > s.records {
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

func (s *daCompleteSnapshot) capacityInput(candidate daCompleteCapacitySet) (daCompleteCapacityInput, error) {
	in := s.input
	in.candidate = candidate
	accounting, err := s.prior.ownerReadyAccounting()
	if err != nil {
		return daCompleteCapacityInput{}, err
	}
	in.priorCredit = accounting.stagedBytes
	txids, tokens := make(map[[32]byte]bool), make(map[PendingOutpointToken]bool)
	if err := s.checkRetainedRecord(s.prior, txids, tokens); err != nil {
		return daCompleteCapacityInput{}, err
	}
	sort.Slice(s.residents, func(i, j int) bool { return bytes.Compare(s.residents[i].daID[:], s.residents[j].daID[:]) < 0 })
	for _, record := range s.residents {
		set, err := s.prepareResident(record, txids, tokens)
		if err != nil {
			return daCompleteCapacityInput{}, err
		}
		in.residents = append(in.residents, set)
	}
	if len(txids) != len(s.locators) {
		return daCompleteCapacityInput{}, errDARelayImageIncompatible
	}
	if err := validateDACompleteCapacity(in); err != nil {
		return daCompleteCapacityInput{}, err
	}
	return in, nil
}

func (s *daCompleteSnapshot) prepareResident(record daRelaySetRecord, txids map[[32]byte]bool, tokens map[PendingOutpointToken]bool) (daCompleteCapacitySet, error) {
	indexes, payloads, err := parseDACompleteMembers(record)
	if err != nil {
		return daCompleteCapacitySet{}, err
	}
	if err := s.checkRetainedRecord(record, txids, tokens); err != nil {
		return daCompleteCapacitySet{}, err
	}
	set, matches, err := sumDACompleteRecord(record, indexes, payloads)
	if err != nil {
		return daCompleteCapacitySet{}, err
	}
	if !matches || record.completeIntrinsic != set || s.checkResidentShape(record, set.payloadBytes) != nil {
		return daCompleteCapacitySet{}, errDARelayImageIncompatible
	}
	return set, nil
}

func (s *daCompleteSnapshot) checkResidentShape(record daRelaySetRecord, payload uint64) error {
	if record.state != daRelayStateCompleteSet || record.commit.member == nil || len(record.chunks) != int(record.commit.chunkCount) {
		return errDARelayImageIncompatible
	}
	if record.revision == 0 || record.revision > s.records || record.receivedTime == 0 || record.receivedTime > s.nextReceivedTime {
		return errDARelayImageIncompatible
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
