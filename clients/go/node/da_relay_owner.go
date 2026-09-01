package node

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type daProvenanceKind uint8

const (
	daProvenanceInvalid daProvenanceKind = iota
	daProvenancePeer
	daProvenanceLocal
	daProvenanceDetachedReorg
)

type DAProvenance struct {
	kind          daProvenanceKind
	peerIdentity  string
	quotaIdentity string
}

type daProvenance = DAProvenance

func NewPeerDAProvenance(peerIdentity, quotaIdentity string) (DAProvenance, error) {
	p := DAProvenance{kind: daProvenancePeer, peerIdentity: peerIdentity, quotaIdentity: quotaIdentity}
	if err := p.validate(); err != nil {
		return DAProvenance{}, err
	}
	return p, nil
}

func LocalDAProvenance() DAProvenance { return DAProvenance{kind: daProvenanceLocal} }

func DetachedReorgDAProvenance() DAProvenance {
	return DAProvenance{kind: daProvenanceDetachedReorg}
}

func (p DAProvenance) quotaKey() string {
	if p.kind == daProvenancePeer {
		return p.quotaIdentity
	}
	return ""
}

func (p DAProvenance) validate() error {
	switch p.kind {
	case daProvenancePeer:
		if p.peerIdentity == "" || p.quotaIdentity == "" {
			return errDAProvenanceInvalid
		}
		return nil
	case daProvenanceLocal, daProvenanceDetachedReorg:
		if p.peerIdentity != "" || p.quotaIdentity != "" {
			return errDAProvenanceInvalid
		}
		return nil
	default:
		return errDAProvenanceInvalid
	}
}

// validate runs only where a member is required, so nil — the empty-slot marker — is refused
// here; a commit slot's emptiness is that pointer, a chunk slot's its map key. Token and fee
// are deliberately NOT checked: a zero token precedes the owner reserve.
func (m *daRelayMemberIdentity) validate() error {
	if m == nil {
		return errDARelayMemberIncomplete
	}
	if m.txid == ([32]byte{}) || m.wtxid == ([32]byte{}) {
		return errDARelayMemberIncomplete
	}
	if len(m.inputs) == 0 || len(m.inputs) > consensus.MAX_TX_INPUTS {
		return errDARelayMemberIncomplete
	}
	return m.provenance.validate()
}

type daRelayOwnerReadyMember struct {
	locator daRelayLocator
	member  daRelayMemberIdentity
	txBytes []byte
	payload []byte
}

type daRelayAdmissionCandidate struct {
	member            daRelayOwnerReadyMember
	payloadCommitment [32]byte
	chunkCount        uint16
	chunkHash         [32]byte
}

type DAAdmissionDisposition uint8

const (
	DAAdmissionRetained  DAAdmissionDisposition = 1
	DAAdmissionDuplicate DAAdmissionDisposition = 2
)

type daRelayAdmissionDisposition = DAAdmissionDisposition

const (
	daRelayAdmissionRetained  = DAAdmissionRetained
	daRelayAdmissionDuplicate = DAAdmissionDuplicate
)

type DAAdmissionResult struct {
	DAID                   [32]byte
	Disposition            DAAdmissionDisposition
	SameDAIDCommitConflict bool
}

type daRelayAdmissionOutcome struct {
	daID                   [32]byte
	disposition            daRelayAdmissionDisposition
	sameDAIDCommitConflict bool
}

type daRelayAdmissionPlan struct {
	image         daRelayRecordImage
	victims       []DAAdmissionVictim
	wouldComplete bool
	stageErr      error
}

type daNonReplayApplyProjection struct {
	placement                                  daRelayRecordPlacement
	member                                     *daRelayMemberIdentity
	receivedTime, sequence                     uint64
	orphanCap, commitCap                       uint64
	projectedOrphanBytes, projectedCommitBytes uint64
	stateB                                     bool
}

func (a *DAAdmission) renderDARelayAdmissionCandidate(provenance daProvenance) (daRelayAdmissionCandidate, error) {
	var zero daRelayAdmissionCandidate
	snapshot := a.Snapshot()
	if err := provenance.validate(); err != nil {
		return zero, err
	}
	if a.tx == nil {
		return zero, errDARelayMemberIncomplete
	}
	candidate := daRelayAdmissionCandidate{member: daRelayOwnerReadyMember{
		member: daRelayMemberIdentity{
			txid:       snapshot.TxID,
			wtxid:      snapshot.WTxID,
			fee:        snapshot.Fee,
			inputs:     snapshot.Inputs,
			provenance: provenance,
		},
		txBytes: snapshot.TxBytes,
	}}
	switch a.tx.TxKind {
	case 0x01:
		return renderDACommitAdmissionCandidate(candidate, a.tx)
	case 0x02:
		return renderDAChunkAdmissionCandidate(candidate, a.tx)
	default:
		return zero, errDARelayMemberIncomplete
	}
}

func (s *DARelayState) admitDANonReplay(admission *DAAdmission, provenance daProvenance) (daRelayAdmissionOutcome, error) {
	candidate, err := admission.renderDARelayAdmissionCandidate(provenance)
	if err != nil {
		return daRelayAdmissionOutcome{}, err
	}
	if s == nil || cmp.Or(s.mempool == nil, admission == nil) || admission.guard == nil ||
		cmp.Or(s.mempool.chainState == nil, s.mempool.pendingOutpoints == nil,
			admission.guard.chainState != s.mempool.chainState, admission.guard.owner != s.mempool.pendingOutpoints) {
		return daRelayAdmissionOutcome{}, errDARelayImageIncompatible
	}
	return s.applyDANonReplayPlan(admission, candidate, s.planDANonReplay(candidate))
}

type daAdmissionObservationKind uint8

const (
	daAdmissionObservationUnavailable daAdmissionObservationKind = iota + 1
	daAdmissionObservationAbsent
	daAdmissionObservationLocated
)

type daAdmissionObservation struct {
	kind                                                    daAdmissionObservationKind
	indexedTxID                                             [32]byte
	indexedLocator                                          daRelayLocator
	recordDAID                                              [32]byte
	recordState                                             daRelaySetState
	recordRevision, recordReceivedTime, recordTTLBlocksLeft uint64
	recordPayloadBytes, recordWireBytes                     uint64
	recordHasReplaceableChunks                              bool
	candidate                                               daRelayAdmissionCandidate
	targetWireBytes                                         uint64
	targetPeerQuotaKey                                      string
	targetHashChecked                                       bool
	stagedCommitPresent                                     bool
	stagedCommitDAID                                        [32]byte
	stagedCommitChunkCount                                  uint16
	stagedCommitWireBytes                                   uint64
	stagedCommitPeerQuotaKey                                string
	stagedCommitRaw                                         bool
}

func (s *DARelayState) AdmitDA(txBytes []byte, provenance DAProvenance) (DAAdmissionResult, error) {
	var zero DAAdmissionResult
	m, owner, err := s.bindDAAdmission()
	if err != nil {
		return zero, err
	}
	if err = provenance.validate(); err != nil {
		return zero, selectRelayDisposition(txAdmitRejected(err.Error()), RelayAdmissionStableTerminalReject)
	}
	owned, tx, txid, wtxid, inputs, err := parseDAAdmissionCandidate(txBytes)
	if err != nil {
		return zero, selectRelayDisposition(err, RelayAdmissionStableTerminalReject)
	}
	hold, err := m.acquireDAAdmissionHold(owner, inputs)
	if err != nil {
		return zero, selectRelayDisposition(err, RelayAdmissionUnavailable)
	}
	defer hold.release()

	replay, exact, err := s.classifyDAReplay(txid, wtxid, owned, owner)
	if err != nil {
		return zero, err
	}
	if exact {
		return replay, nil
	}
	return s.admitDANonExact(hold, owned, tx, txid, wtxid, inputs, provenance)
}
func (s *DARelayState) admitDANonExact(hold *daAdmissionHold, owned []byte, tx *consensus.Tx, txid, wtxid [32]byte, inputs []consensus.Outpoint, provenance DAProvenance) (DAAdmissionResult, error) {
	admission, err := hold.validateDACandidate(owned, tx, txid, wtxid, inputs)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	defer admission.Close()
	outcome, err := s.admitDANonReplay(admission, provenance)
	if err != nil {
		return DAAdmissionResult{}, err
	}
	return publicDAAdmissionResult(outcome)
}
func (s *DARelayState) bindDAAdmission() (*Mempool, *PendingOutpointOwner, error) {
	switch {
	case s == nil:
		return nil, nil, selectRelayDisposition(txAdmitUnavailable("nil DA relay"), RelayAdmissionUnavailable)
	case s.mempool == nil:
		return nil, nil, selectRelayDisposition(txAdmitUnavailable("nil mempool"), RelayAdmissionUnavailable)
	case s.mempool.chainState == nil:
		return nil, nil, selectRelayDisposition(txAdmitUnavailable("nil chainstate"), RelayAdmissionUnavailable)
	case s.mempool.pendingOutpoints == nil:
		return nil, nil, selectRelayDisposition(txAdmitUnavailable("nil pending-outpoint owner"), RelayAdmissionUnavailable)
	default:
		return s.mempool, s.mempool.pendingOutpoints, nil
	}
}
func (s *DARelayState) classifyDAReplay(txid, wtxid [32]byte, owned []byte, owner *PendingOutpointOwner) (DAAdmissionResult, bool, error) {
	observation := s.observeDAAdmission(txid)
	switch observation.kind {
	case daAdmissionObservationUnavailable:
		return DAAdmissionResult{}, false, selectRelayDisposition(txAdmitUnavailable("DA relay owner maps unavailable"), RelayAdmissionUnavailable)
	case daAdmissionObservationAbsent:
		return DAAdmissionResult{}, false, nil
	case daAdmissionObservationLocated:
		if err := observation.validateDAAdmissionObservation(owner); err != nil {
			return DAAdmissionResult{}, false, selectRelayDisposition(txAdmitRejected(err.Error()), RelayAdmissionInternal)
		}
		if wtxid == observation.candidate.member.member.wtxid && bytes.Equal(owned, observation.candidate.member.txBytes) {
			return DAAdmissionResult{DAID: observation.recordDAID, Disposition: DAAdmissionDuplicate}, true, nil
		}
		return DAAdmissionResult{}, false, nil
	default:
		return DAAdmissionResult{}, false, selectRelayDisposition(txAdmitRejected(errDARelayImageIncompatible.Error()), RelayAdmissionInternal)
	}
}
func publicDAAdmissionResult(outcome daRelayAdmissionOutcome) (DAAdmissionResult, error) {
	switch outcome.disposition {
	case daRelayAdmissionRetained, daRelayAdmissionDuplicate:
		return DAAdmissionResult{DAID: outcome.daID, Disposition: outcome.disposition, SameDAIDCommitConflict: outcome.sameDAIDCommitConflict}, nil
	default:
		return DAAdmissionResult{}, selectRelayDisposition(txAdmitRejected(errDARelayImageIncompatible.Error()), RelayAdmissionInternal)
	}
}
func (s *DARelayState) observeDAAdmission(txid [32]byte) daAdmissionObservation {
	if s == nil {
		return daAdmissionObservation{kind: daAdmissionObservationUnavailable}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sets == nil || s.locators == nil {
		return daAdmissionObservation{kind: daAdmissionObservationUnavailable}
	}
	locator, found := s.locators[txid]
	if !found {
		return daAdmissionObservation{kind: daAdmissionObservationAbsent}
	}
	observation := daAdmissionObservation{kind: daAdmissionObservationLocated, indexedTxID: txid, indexedLocator: locator}
	record, found := s.sets[locator.daID]
	if !found {
		return observation
	}
	observation.recordDAID = record.daID
	observation.recordState = record.state
	observation.recordRevision = record.revision
	observation.recordReceivedTime = record.receivedTime
	observation.recordTTLBlocksLeft = record.ttlBlocksRemaining
	observation.recordPayloadBytes = record.payloadBytes
	observation.recordWireBytes = record.wireBytes
	observation.recordHasReplaceableChunks = record.replaceableChunks != nil
	observation.stagedCommitPresent = record.commit.member != nil
	observation.stagedCommitDAID = record.commit.daID
	observation.stagedCommitChunkCount = record.commit.chunkCount
	observation.stagedCommitWireBytes = record.commit.wireBytes
	observation.stagedCommitPeerQuotaKey = record.commit.peerQuotaKey
	observation.stagedCommitRaw = len(record.commit.txBytes) != 0
	observation.captureDAAdmissionTarget(locator, record)
	return observation
}
func (o *daAdmissionObservation) captureDAAdmissionTarget(locator daRelayLocator, record daRelaySetRecord) {
	switch locator.kind {
	case daRelayLocatorCommit:
		o.candidate.member.locator = daRelayLocator{daID: record.commit.daID, kind: daRelayLocatorCommit}
		member := record.commit.member.clone()
		o.candidate.member.txBytes = append([]byte(nil), record.commit.txBytes...)
		o.candidate.payloadCommitment, o.candidate.chunkCount = record.commit.payloadCommitment, record.commit.chunkCount
		o.targetWireBytes, o.targetPeerQuotaKey = record.commit.wireBytes, record.commit.peerQuotaKey
		if member != nil {
			o.candidate.member.member = *member
		}
	case daRelayLocatorChunk:
		chunk := record.chunks[locator.chunkIndex]
		o.candidate.member.locator = daRelayLocator{daID: chunk.daID, kind: daRelayLocatorChunk, chunkIndex: chunk.chunkIndex}
		member := chunk.member.clone()
		o.candidate.member.txBytes = append([]byte(nil), chunk.txBytes...)
		o.candidate.member.payload = slices.Clone(chunk.payload)
		o.candidate.chunkHash = chunk.chunkHash
		o.targetWireBytes, o.targetPeerQuotaKey, o.targetHashChecked = chunk.wireBytes, chunk.peerQuotaKey, chunk.hashChecked
		if member != nil {
			o.candidate.member.member = *member
		}
	}
}
func (o daAdmissionObservation) validateDAAdmissionObservation(owner *PendingOutpointOwner) error {
	switch {
	case o.validateHeader() != nil, o.validateToken(owner) != nil, o.validateRole() != nil, checkOwnerReadyRetainedBytes(o.candidate.member.txBytes) != nil:
		return errDARelayImageIncompatible
	}
	tx, parsedTxID, parsedWTxID, err := parseRelayMetadataTx(o.candidate.member.txBytes)
	if err != nil {
		return errDARelayImageIncompatible
	}
	inputs := relayMetadataInputs(tx)
	type txidPair struct{ member, parsed [32]byte }
	if slices.Contains([]bool{!isDAAdmissionTx(tx), uint(len(inputs)-1) >= uint(consensus.MAX_TX_INPUTS), (txidPair{o.candidate.member.member.txid, parsedTxID}) != (txidPair{o.indexedTxID, o.indexedTxID}), parsedWTxID != o.candidate.member.member.wtxid, !slices.Equal(inputs, o.candidate.member.member.inputs)}, true) {
		return errDARelayImageIncompatible
	}
	return o.validateRetained(tx)
}
func (o daAdmissionObservation) validateHeader() error {
	type header struct {
		kind    daAdmissionObservationKind
		locator daRelayLocator
		daID    [32]byte
	}
	if (header{o.kind, o.indexedLocator, o.recordDAID}) != (header{daAdmissionObservationLocated, o.candidate.member.locator, o.indexedLocator.daID}) {
		return errDARelayImageIncompatible
	}
	if slices.Contains([]bool{o.recordRevision == 0, o.recordReceivedTime == 0, o.recordState > daRelayStateCompleteSet}, true) {
		return errDARelayImageIncompatible
	}
	var invalid bool
	switch o.recordState {
	case daRelayStateOrphanChunks, daRelayStateStagedCommit:
		invalid = slices.Contains([]bool{o.recordTTLBlocksLeft == 0, o.recordPayloadBytes != 0, o.recordWireBytes != 0, o.recordHasReplaceableChunks}, true)
	case daRelayStateCompleteSet:
		invalid = slices.Contains([]bool{o.recordTTLBlocksLeft != 0, o.recordPayloadBytes == 0, o.recordWireBytes <= uint64(len(o.candidate.member.txBytes)), o.recordHasReplaceableChunks}, true)
	default:
		invalid = true
	}
	if invalid {
		return errDARelayImageIncompatible
	}
	return nil
}
func (o daAdmissionObservation) validateToken(owner *PendingOutpointOwner) error {
	token := o.candidate.member.member.token
	switch owner {
	case nil:
		if token != (PendingOutpointToken{}) {
			return errDARelayImageIncompatible
		}
	default:
		if token.owner != owner {
			return errDARelayImageIncompatible
		}
		if token.seq == 0 {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

func (o daAdmissionObservation) validateRole() error {
	switch o.candidate.member.locator.kind {
	case daRelayLocatorCommit:
		return o.validateCommitRole()
	case daRelayLocatorChunk:
		return o.validateChunkRole()
	default:
		return errDARelayImageIncompatible
	}
}

func (o daAdmissionObservation) validateCommitRole() error {
	if o.recordState != daRelayStateStagedCommit && o.recordState != daRelayStateCompleteSet {
		return errDARelayImageIncompatible
	}
	type role struct {
		index             uint16
		daID              [32]byte
		wireBytes         uint64
		peerQuotaKey      string
		payloadByteLength int
	}
	if (role{o.candidate.member.locator.chunkIndex, o.candidate.member.locator.daID, o.targetWireBytes, o.targetPeerQuotaKey, len(o.candidate.member.payload)}) !=
		(role{daID: o.recordDAID}) {
		return errDARelayImageIncompatible
	}
	if o.candidate.chunkCount == 0 {
		return errDARelayImageIncompatible
	}
	if uint64(o.candidate.chunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayImageIncompatible
	}
	return o.validateStagedCommit()
}

func (o daAdmissionObservation) validateChunkRole() error {
	switch o.recordState {
	case daRelayStateOrphanChunks, daRelayStateStagedCommit, daRelayStateCompleteSet:
	default:
		return errDARelayImageIncompatible
	}
	type role struct {
		daID         [32]byte
		index        uint16
		wireBytes    uint64
		peerQuotaKey string
		hashChecked  bool
	}
	if (role{o.candidate.member.locator.daID, o.candidate.member.locator.chunkIndex, o.targetWireBytes, o.targetPeerQuotaKey, o.targetHashChecked}) !=
		(role{daID: o.recordDAID, index: o.candidate.member.locator.chunkIndex}) {
		return errDARelayImageIncompatible
	}
	return o.validateStagedCommit()
}

func (o daAdmissionObservation) validateStagedCommit() error {
	switch o.recordState {
	case daRelayStateOrphanChunks:
		type emptyCommit struct {
			present    bool
			daID       [32]byte
			chunkCount uint16
			wireBytes  uint64
			peerQuota  string
			rawPresent bool
		}
		if (emptyCommit{o.stagedCommitPresent, o.stagedCommitDAID, o.stagedCommitChunkCount, o.stagedCommitWireBytes, o.stagedCommitPeerQuotaKey, o.stagedCommitRaw}) != (emptyCommit{}) {
			return errDARelayImageIncompatible
		}
		return nil
	case daRelayStateStagedCommit, daRelayStateCompleteSet:
	default:
		return errDARelayImageIncompatible
	}
	type stagedCommit struct {
		present    bool
		daID       [32]byte
		wireBytes  uint64
		peerQuota  string
		rawPresent bool
	}
	if (stagedCommit{o.stagedCommitPresent, o.stagedCommitDAID, o.stagedCommitWireBytes, o.stagedCommitPeerQuotaKey, o.stagedCommitRaw}) !=
		(stagedCommit{present: true, daID: o.recordDAID, rawPresent: true}) {
		return errDARelayImageIncompatible
	}
	if o.stagedCommitChunkCount == 0 {
		return errDARelayImageIncompatible
	}
	if uint64(o.stagedCommitChunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayImageIncompatible
	}
	if o.candidate.member.locator.chunkIndex >= o.stagedCommitChunkCount {
		return errDARelayImageIncompatible
	}
	return nil
}

func (o daAdmissionObservation) validateRetained(tx *consensus.Tx) error {
	candidate := o.candidate
	candidate.member.member.token = PendingOutpointToken{}
	var rendered daRelayAdmissionCandidate
	var err error
	switch candidate.member.locator.kind {
	case daRelayLocatorCommit:
		rendered, err = renderDACommitAdmissionCandidate(candidate, tx)
	case daRelayLocatorChunk:
		retainedPayload := candidate.member.payload
		candidate.member.payload = tx.DaPayload
		if !matchingDAChunkPayloadHash(tx) {
			return errDARelayImageIncompatible
		}
		if o.recordState == daRelayStateCompleteSet {
			if slices.Contains([]bool{retainedPayload != nil, o.recordPayloadBytes < uint64(len(tx.DaPayload))}, true) {
				return errDARelayImageIncompatible
			}
		} else if !bytes.Equal(tx.DaPayload, retainedPayload) {
			return errDARelayImageIncompatible
		}
		rendered, err = renderDAChunkAdmissionCandidate(candidate, tx)
	default:
		return errDARelayImageIncompatible
	}
	if slices.Contains([]bool{err != nil, !sameDAAdmissionCandidate(rendered, candidate)}, true) {
		return errDARelayImageIncompatible
	}
	return nil
}
func sameDAAdmissionCandidate(left, right daRelayAdmissionCandidate) bool {
	type scalar struct {
		locator                      daRelayLocator
		txid, wtxid                  [32]byte
		fee                          consensus.Uint128
		token                        PendingOutpointToken
		provenance                   daProvenance
		payloadCommitment, chunkHash [32]byte
		chunkCount                   uint16
	}
	return scalar{left.member.locator, left.member.member.txid, left.member.member.wtxid, left.member.member.fee, left.member.member.token, left.member.member.provenance, left.payloadCommitment, left.chunkHash, left.chunkCount} ==
		scalar{right.member.locator, right.member.member.txid, right.member.member.wtxid, right.member.member.fee, right.member.member.token, right.member.member.provenance, right.payloadCommitment, right.chunkHash, right.chunkCount} &&
		slices.Equal(left.member.member.inputs, right.member.member.inputs) && bytes.Equal(left.member.txBytes, right.member.txBytes) && bytes.Equal(left.member.payload, right.member.payload)
}

func (s *DARelayState) planDANonReplay(candidate daRelayAdmissionCandidate) daRelayAdmissionPlan {
	s.mu.Lock()
	current, present := s.sets[candidate.member.locator.daID]
	current = current.cloneOwnerReady()
	s.mu.Unlock()

	plan := daRelayAdmissionPlan{image: daRelayRecordImage{
		daID: candidate.member.locator.daID, present: present, baseline: current.revision,
	}}
	if present {
		if err := current.checkDANonReplayPrior(candidate.member.locator.daID, s.mempool.pendingOutpoints); err != nil {
			plan.stageErr = err
			return plan
		}
	}
	if err := checkOwnerReadySlotFree(current, candidate.member.locator); err != nil {
		plan.stageErr = err
		return plan
	}
	plan.image, plan.victims = stageDANonReplayCandidate(current, present, candidate, s.caps.orphanTTLBlocks)
	plan.wouldComplete = plan.image.next.completeByShape()
	return plan
}

func (s *DARelayState) applyDANonReplayPlan(admission *DAAdmission, candidate daRelayAdmissionCandidate, plan daRelayAdmissionPlan) (daRelayAdmissionOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if outcome, duplicate := s.duplicateDANonReplayLocked(candidate); duplicate {
		return outcome, nil
	}
	projection, err := s.prepareDANonReplayProjectionLocked(plan, candidate)
	if err = cmp.Or(err, s.preflightDANonReplayInstall(projection)); err != nil {
		return daRelayAdmissionOutcome{}, err
	}
	placement := projection.placement
	member, receivedTime, sequence := projection.member, projection.receivedTime, projection.sequence
	stateB, orphanCap, commitCap := projection.stateB, projection.orphanCap, projection.commitCap
	projectedOrphanBytes, projectedCommitBytes := projection.projectedOrphanBytes, projection.projectedCommitBytes
	commit, err := admission.BeginCommit(plan.victims)
	if err != nil {
		return daRelayAdmissionOutcome{}, err
	}
	if stateB && projectedOrphanBytes > orphanCap {
		commit.Abort()
		return daRelayAdmissionOutcome{}, errDARelayOrphanPoolCapExceeded
	}
	if stateB && projectedCommitBytes > commitCap {
		commit.Abort()
		return daRelayAdmissionOutcome{}, errDARelayOrphanCommitCapExceeded
	}
	member.token = commit.CandidateToken()
	placement.record.receivedTime = receivedTime
	s.nextReceivedTime = sequence
	s.installDASetRecordLocked(placement)
	commit.Commit()
	return daRelayAdmissionOutcome{daID: candidate.member.locator.daID, disposition: daRelayAdmissionRetained}, nil
}

func (s *DARelayState) preflightDANonReplayInstall(projection daNonReplayApplyProjection) error {
	if slices.Contains([]bool{projection.member == nil, s.sets == nil, s.locators == nil, s.orphanBytesByPeerQuotaKey == nil, s.orphanBytesByDAID == nil}, true) {
		return errDARelayImageIncompatible
	}
	return nil
}

func (s *DARelayState) prepareDANonReplayProjectionLocked(plan daRelayAdmissionPlan, candidate daRelayAdmissionCandidate) (daNonReplayApplyProjection, error) {
	current, present := s.sets[plan.image.daID]
	if present != plan.image.present || current.revision != plan.image.baseline {
		return daNonReplayApplyProjection{}, selectRelayDisposition(txAdmitUnavailable("retained DA record moved while this admission was planned"), RelayAdmissionUnavailable)
	}

	if plan.stageErr != nil {
		return daNonReplayApplyProjection{}, plan.stageErr
	}
	live, err := s.checkDARecordImageBaselineLocked(plan.image)
	if err != nil {
		return daNonReplayApplyProjection{}, err
	}
	if err := checkDANonReplayVictims(plan.image, live, plan.victims); err != nil {
		return daNonReplayApplyProjection{}, err
	}
	if plan.wouldComplete {
		return daNonReplayApplyProjection{}, selectRelayDisposition(txAdmitUnavailable("DA COMPLETE_SET capacity owner is not active"), RelayAdmissionUnavailable)
	}
	return s.projectDANonReplayAdmissionLocked(plan.image, candidate, live)
}

func (s *DARelayState) projectDANonReplayAdmissionLocked(image daRelayRecordImage, candidate daRelayAdmissionCandidate, live daRelaySetRecord) (daNonReplayApplyProjection, error) {
	sequence, err := s.nextDANonReplaySequenceLocked(image)
	if err != nil {
		return daNonReplayApplyProjection{}, err
	}
	stateB, projectionCaps := image.next.state == daRelayStateStagedCommit, s.caps
	orphanCap, daCap, peerCap, commitCap := s.caps.orphanPoolBytes, s.caps.orphanPoolPerDAIDBytes, s.caps.orphanPoolPerPeerBytes, s.caps.orphanCommitOverheadBytes
	projectionCaps.orphanPoolBytes, projectionCaps.orphanPoolPerDAIDBytes = ^uint64(0), ^uint64(0)
	projectionCaps.orphanPoolPerPeerBytes, projectionCaps.orphanCommitOverheadBytes = ^uint64(0), ^uint64(0)
	placement, err := s.projectDARecordImageLiveLocked(image, live, projectionCaps)
	if err != nil {
		return daNonReplayApplyProjection{}, err
	}
	member, receivedTime := prepareDANonReplayInstall(&placement, candidate.member.locator, sequence)
	projection := daNonReplayApplyProjection{
		placement: placement, member: member, receivedTime: receivedTime, sequence: sequence,
		orphanCap: orphanCap, commitCap: commitCap, projectedOrphanBytes: placement.orphanBytes, projectedCommitBytes: placement.commitBytes, stateB: stateB,
	}
	if stateB {
		return projection, nil
	}
	if placement.orphanBytes > orphanCap {
		return daNonReplayApplyProjection{}, errDARelayOrphanPoolCapExceeded
	}
	if placement.daBytes > daCap {
		return daNonReplayApplyProjection{}, errDARelayOrphanDAIDCapExceeded
	}
	for _, value := range placement.peerBytes {
		if value > peerCap {
			return daNonReplayApplyProjection{}, errDARelayOrphanPeerCapExceeded
		}
	}
	return projection, nil
}

func (s *DARelayState) duplicateDANonReplayLocked(candidate daRelayAdmissionCandidate) (daRelayAdmissionOutcome, bool) {
	outcome := daRelayAdmissionOutcome{daID: candidate.member.locator.daID, disposition: daRelayAdmissionDuplicate}
	if _, duplicate := s.locators[candidate.member.member.txid]; duplicate {
		return outcome, true
	}
	record := s.sets[candidate.member.locator.daID]
	if candidate.member.locator.kind == daRelayLocatorCommit && record.commit.member != nil {
		outcome.sameDAIDCommitConflict = record.commit.member.txid != candidate.member.member.txid
		return outcome, true
	}
	_, duplicate := record.chunks[candidate.member.locator.chunkIndex]
	return outcome, candidate.member.locator.kind == daRelayLocatorChunk && duplicate
}

func (s *DARelayState) nextDANonReplaySequenceLocked(image daRelayRecordImage) (uint64, error) {
	if image.present {
		live := s.sets[image.daID]
		if s.nextReceivedTime < live.receivedTime || s.records < live.revision {
			return 0, errDARelayImageIncompatible
		}
	}
	return checkedAddUint64(s.nextReceivedTime, 1)
}

func prepareDANonReplayInstall(placement *daRelayRecordPlacement, locator daRelayLocator, sequence uint64) (*daRelayMemberIdentity, uint64) {
	receivedTime := placement.record.receivedTime
	if receivedTime == 0 {
		receivedTime = sequence
	}
	if locator.kind == daRelayLocatorCommit {
		return placement.record.commit.member, receivedTime
	}
	return placement.record.chunks[locator.chunkIndex].member, receivedTime
}

func renderDACommitAdmissionCandidate(candidate daRelayAdmissionCandidate, tx *consensus.Tx) (daRelayAdmissionCandidate, error) {
	var zero daRelayAdmissionCandidate
	if tx.DaCommitCore == nil || tx.DaChunkCore != nil {
		return zero, errDARelayMemberIncomplete
	}
	if tx.DaCommitCore.ChunkCount == 0 || uint64(tx.DaCommitCore.ChunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return zero, errDARelayChunkCountInvalid
	}
	commitment, err := daAdmissionPayloadCommitment(tx)
	if err != nil {
		return zero, err
	}
	candidate.member.locator = daRelayLocator{daID: tx.DaCommitCore.DaID, kind: daRelayLocatorCommit}
	candidate.payloadCommitment = commitment
	candidate.chunkCount = tx.DaCommitCore.ChunkCount
	if err := candidate.validate(); err != nil {
		return zero, err
	}
	return candidate, nil
}

func renderDAChunkAdmissionCandidate(candidate daRelayAdmissionCandidate, tx *consensus.Tx) (daRelayAdmissionCandidate, error) {
	var zero daRelayAdmissionCandidate
	if tx.DaChunkCore == nil || tx.DaCommitCore != nil {
		return zero, errDARelayMemberIncomplete
	}
	if err := checkOwnerReadyChunkIndex(tx.DaChunkCore.ChunkIndex); err != nil {
		return zero, err
	}
	if err := checkOwnerReadyPayload(tx.DaPayload); err != nil {
		return zero, err
	}
	candidate.member.locator = daRelayLocator{daID: tx.DaChunkCore.DaID, kind: daRelayLocatorChunk, chunkIndex: tx.DaChunkCore.ChunkIndex}
	candidate.member.payload = append([]byte(nil), tx.DaPayload...)
	candidate.chunkHash = tx.DaChunkCore.ChunkHash
	if err := candidate.validate(); err != nil {
		return zero, err
	}
	return candidate, nil
}

func (c daRelayAdmissionCandidate) validate() error {
	if err := c.member.validate(); err != nil {
		return err
	}
	if c.member.member.token != (PendingOutpointToken{}) {
		return errDARelayMemberIncomplete
	}
	if c.member.locator.kind == daRelayLocatorCommit {
		return c.validateCommit()
	}
	return c.validateChunk()
}

func (c daRelayAdmissionCandidate) validateCommit() error {
	if c.chunkHash != ([32]byte{}) {
		return errDARelayMemberIncomplete
	}
	if c.chunkCount == 0 || uint64(c.chunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayChunkCountInvalid
	}
	return nil
}

func (c daRelayAdmissionCandidate) validateChunk() error {
	if c.payloadCommitment != ([32]byte{}) || c.chunkCount != 0 {
		return errDARelayMemberIncomplete
	}
	return nil
}

func daAdmissionPayloadCommitment(tx *consensus.Tx) ([32]byte, error) {
	var commitment [32]byte
	found := false
	for _, output := range tx.Outputs {
		if output.CovenantType != consensus.COV_TYPE_DA_COMMIT {
			continue
		}
		if found || len(output.CovenantData) != len(commitment) {
			return [32]byte{}, errDARelayMemberIncomplete
		}
		copy(commitment[:], output.CovenantData)
		found = true
	}
	if !found {
		return [32]byte{}, errDARelayMemberIncomplete
	}
	return commitment, nil
}

// A commit locator must carry chunk index 0, or two locators for one slot would
// compare unequal. Every absolute bound below has ONE definition, shared with the
// record path that installDASetRecordLocked publishes. The descriptor carries neither the DECLARED
// chunk count nor wire_bytes, so this slice binds neither; the admission candidate keeps
// role-specific metadata separately, while legacy wireBytes remains zero.
func (m daRelayOwnerReadyMember) validate() error {
	switch m.locator.kind {
	case daRelayLocatorCommit:
		if m.locator.chunkIndex != 0 || len(m.payload) != 0 {
			return errDARelayMemberIncomplete
		}
	case daRelayLocatorChunk:
		if err := checkOwnerReadyChunkIndex(m.locator.chunkIndex); err != nil {
			return err
		}
		if err := checkOwnerReadyPayload(m.payload); err != nil {
			return err
		}
	default:
		return errDARelayMemberIncomplete
	}
	if err := checkOwnerReadyRetainedBytes(m.txBytes); err != nil {
		return err
	}
	return m.member.validate()
}

func checkOwnerReadyChunkIndex(chunkIndex uint16) error {
	if uint64(chunkIndex) >= consensus.MAX_DA_CHUNK_COUNT {
		return errDARelayChunkIndexOutOfRange
	}
	return nil
}

func checkOwnerReadyPayload(payload []byte) error {
	if len(payload) == 0 {
		return errDARelayMemberIncomplete
	}
	if uint64(len(payload)) > consensus.CHUNK_BYTES {
		return errDARelayChunkPayloadSizeInvalid
	}
	return nil
}

func checkOwnerReadyRetainedBytes(txBytes []byte) error {
	if len(txBytes) == 0 || len(txBytes) > consensus.MAX_RELAY_MSG_BYTES {
		return errDARelayMemberIncomplete
	}
	return nil
}

// checkOwnerReadyRecord reads no revision, so one check serves both the resident
// pre-state and the staged record. It reads the values installDASetRecordLocked
// publishes, so a record edited after staging is refused on the descriptor's terms.
//
// Legacy wireBytes is pinned to zero at all three levels — record, commit and
// chunk — which is the INVERSE of the legacy validators, which refuse a zero. That
// is the point: withoutPeerQuotaKey returns early on a zero record wireBytes, and
// its commit and chunk arms on a zero of their own, so no owner-ready image can
// reactivate that path. Owner-ready legacy wireBytes remains zero in every
// successor slice; separate role-specific accounting authority does not
// reactivate the legacy path.
func (r daRelaySetRecord) checkOwnerReadyRecord() error {
	// Only these two states have a charge formula here; the COMPLETE_SET domain
	// was not assigned to this slice.
	if r.state != daRelayStateOrphanChunks && r.state != daRelayStateStagedCommit {
		return errDARelayImageIncompatible
	}
	if r.wireBytes != 0 {
		return errDARelayImageIncompatible
	}
	if err := r.checkOwnerReadyCommitSlot(); err != nil {
		return err
	}
	for _, index := range sortedRetainedDAChunkIndexes(r) {
		if err := r.checkOwnerReadyChunk(index); err != nil {
			return err
		}
	}
	return nil
}

func (r daRelaySetRecord) checkOwnerReadyCommitSlot() error {
	if r.commit.wireBytes != 0 {
		return errDARelayImageIncompatible
	}
	if r.commit.member == nil {
		if r.commit.chunkCount != 0 || len(r.commit.txBytes) != 0 {
			return errDARelayMemberIncomplete
		}
		return nil
	}
	if r.commit.daID != r.daID {
		return errDARelayMemberIncomplete
	}
	if err := checkOwnerReadyRetainedBytes(r.commit.txBytes); err != nil {
		return err
	}
	return r.commit.member.validate()
}

func (r daRelaySetRecord) checkOwnerReadyChunk(index uint16) error {
	chunk := r.chunks[index]
	if chunk.chunkIndex != index || chunk.daID != r.daID {
		return errDARelayMemberIncomplete
	}
	if chunk.wireBytes != 0 {
		return errDARelayImageIncompatible
	}
	if err := checkOwnerReadyChunkIndex(index); err != nil {
		return err
	}
	if err := checkOwnerReadyPayload(chunk.payload); err != nil {
		return err
	}
	if err := checkOwnerReadyRetainedBytes(chunk.txBytes); err != nil {
		return err
	}
	return chunk.member.validate()
}
