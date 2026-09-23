package node

import (
	"bytes"
	"maps"
	"math"
	"slices"
)

// The plan is exclusive, single-use scratch; public admission remains on the existing non-completing path.
type daCompleteCommitPlan struct {
	relay            *DARelayState
	admission        *DAAdmission
	duplicate        *daRelayAdmissionOutcome
	source           *daCompleteSnapshot
	projected        *DARelayState
	owner            *daPreparedAdmissionCommit
	original         []DAAdmissionVictim
	prefetch         [][32]byte
	member           *daRelayMemberIdentity
	outcome          daRelayAdmissionOutcome
	capacityRejected bool
	mismatch         bool
	sharedBytes      uint64
}

func (s *DARelayState) prepareDACompleteCommit(admission *DAAdmission, result daCompletePreparation) (*daCompleteCommitPlan, error) {
	if result.duplicate != nil {
		return s.prepareDACompleteDuplicate(admission, result)
	}
	source, err := daCompleteCommitSource(result)
	if err != nil {
		return nil, err
	}
	admission.mustLiveValue()
	if admission.guard.state.Load() != daAdmissionOpen {
		return nil, errDARelayImageIncompatible
	}
	p := &daCompleteCommitPlan{relay: s, admission: admission}
	if !s.sameDACompleteAdmission(admission, source) {
		return nil, errDARelayImageIncompatible
	}
	if result.mismatch != nil && result.mismatch.kind == daRelayLocatorChunk {
		return nil, ErrDARelayPayloadCommitmentMismatch
	}
	p.source = source
	if err := p.prepareEffects(result); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *DARelayState) prepareDACompleteDuplicate(admission *DAAdmission, result daCompletePreparation) (*daCompleteCommitPlan, error) {
	if result.prepared != nil || result.mismatch != nil || result.duplicate.disposition != daRelayAdmissionDuplicate {
		return nil, errDARelayImageIncompatible
	}
	admission.mustLiveValue()
	if admission.guard.state.Load() != daAdmissionOpen {
		return nil, errDARelayImageIncompatible
	}
	duplicate := *result.duplicate
	return &daCompleteCommitPlan{relay: s, admission: admission, duplicate: &duplicate}, nil
}

func daCompleteCommitSource(result daCompletePreparation) (*daCompleteSnapshot, error) {
	switch [3]bool{result.duplicate != nil, result.prepared != nil, result.mismatch != nil} {
	case [3]bool{false, true, false}:
		if result.prepared.image.next.state != daRelayStateCompleteSet {
			return nil, errDARelayImageIncompatible
		}
		return result.prepared.source, nil
	case [3]bool{false, false, true}:
		return daCompleteMismatchSource(result.mismatch)
	default:
		return nil, errDARelayImageIncompatible
	}
}

func daCompleteMismatchSource(m *daCompleteMismatch) (*daCompleteSnapshot, error) {
	if m.source == nil || m.kind != m.source.candidate.member.locator.kind {
		return nil, errDARelayImageIncompatible
	}
	if m.kind != daRelayLocatorCommit && m.kind != daRelayLocatorChunk {
		return nil, errDARelayImageIncompatible
	}
	if m.image.next.state != daRelayStateStagedCommit {
		return nil, errDARelayImageIncompatible
	}
	return m.source, nil
}

func (s *DARelayState) sameDACompleteAdmission(a *DAAdmission, source *daCompleteSnapshot) bool {
	if source == nil || source.publicationBase == nil {
		return false
	}
	if s.mempool != source.publicationBase.mempool || source.owner != a.guard.owner || s.mempool.pendingOutpoints != source.owner {
		return false
	}
	m, snapshot := source.candidate.member, a.snapshot
	return [2][32]byte{m.member.txid, m.member.wtxid} == [2][32]byte{snapshot.TxID, snapshot.WTxID} &&
		m.member.fee == snapshot.Fee && sameDACompleteAdmissionBuffers(m, snapshot)
}

func sameDACompleteAdmissionBuffers(m daRelayOwnerReadyMember, snapshot DAAdmissionSnapshot) bool {
	return bytes.Equal(m.txBytes, snapshot.TxBytes) && slices.Equal(m.member.inputs, snapshot.Inputs)
}

func (p *daCompleteCommitPlan) prepareEffects(result daCompletePreparation) error {
	var image daRelayRecordImage
	var victims []DAAdmissionVictim
	var capacity daCompleteCapacityPlan
	var err error
	if result.prepared != nil {
		capacity, err = planDACompleteCapacity(result.prepared.input)
		image, victims = result.prepared.image, result.prepared.pruned
		p.capacityRejected = !capacity.accepted
		if p.capacityRejected {
			victims = nil
		}
	} else {
		image, victims = result.mismatch.image, result.mismatch.removed
		p.mismatch = true
	}
	if err != nil {
		return err
	}
	p.projected = p.source.publicationBase.cloneForAtomicBatchLocked()
	p.original = daCompleteRecordClaims(p.source.prior)
	for _, record := range p.source.residents {
		p.original = append(p.original, daCompleteRecordClaims(record)...)
	}
	victims = slices.Clone(victims)
	for _, id := range capacity.victims {
		victims = append(victims, daCompleteRecordClaims(p.projected.sets[id])...)
		p.removeRecord(id)
	}
	p.owner, err = prepareDAAdmissionCommit(p.admission, victims)
	if err != nil {
		return selectRelayDisposition(txAdmitFromPendingOutpointError(err), relayDispositionForOwnerError(err))
	}
	return p.projectCompletion(image.next.cloneOwnerReady(), capacity)
}

func daCompleteRecordClaims(record daRelaySetRecord) []DAAdmissionVictim {
	rows := record.locatorRows()
	claims := make([]DAAdmissionVictim, 0, len(rows))
	for _, row := range rows {
		member := record.commit.member
		if row.locator.kind == daRelayLocatorChunk {
			member = record.chunks[row.locator.chunkIndex].member
		}
		claims = append(claims, DAAdmissionVictim{TxID: member.txid, Token: member.token, Inputs: slices.Clone(member.inputs)})
	}
	return claims
}

func (p *daCompleteCommitPlan) removeRecord(id [32]byte) {
	for _, row := range p.projected.sets[id].locatorRows() {
		delete(p.projected.locators, row.txid)
	}
	delete(p.projected.sets, id)
	p.prefetch = append(p.prefetch, id)
}

func (p *daCompleteCommitPlan) projectCompletion(next daRelaySetRecord, capacity daCompleteCapacityPlan) error {
	s := p.projected
	old := p.source.prior
	// The existing counter projector only sees A/B. C totals come from its planner.
	billed := daRelaySetRecord{daID: old.daID}
	if p.mismatch {
		billed = next
	}
	caps := s.caps
	caps.stagedBytes, caps.orphanPoolBytes, caps.orphanPoolPerDAIDBytes = math.MaxUint64, math.MaxUint64, math.MaxUint64
	caps.orphanPoolPerPeerBytes, caps.orphanCommitOverheadBytes = math.MaxUint64, math.MaxUint64
	accounting, err := s.projectDARecordImageCountersLocked(daRelayRecordImage{daID: old.daID, next: billed}, old, caps)
	if err != nil {
		return err
	}
	s.stagedBytes, s.orphanBytes, s.orphanCommitOverheadBytes = accounting.stagedBytes, accounting.orphanBytes, accounting.commitBytes
	s.applyProjectedPeerBytes(accounting.peerBytes)
	s.applyProjectedDAIDBytes(old.daID, accounting.daBytes)
	if err := p.projectCompleteTotals(capacity); err != nil {
		return err
	}
	next.revision, err = checkedAddUint64(p.source.records, 1)
	if err != nil {
		return err
	}
	p.removeRecord(old.daID)
	s.records = next.revision
	// Mismatch sequence exhaustion is selected after Reserve and both B bounds.
	s.nextReceivedTime = p.source.nextReceivedTime + 1
	next.receivedTime = old.receivedTime
	s.sets[old.daID] = next
	for _, row := range next.locatorRows() {
		s.locators[row.txid] = row.locator
	}
	p.member = next.commit.member
	if p.source.candidate.member.locator.kind == daRelayLocatorChunk {
		p.member = next.chunks[p.source.candidate.member.locator.chunkIndex].member
	}
	p.outcome = daRelayAdmissionOutcome{daID: old.daID, disposition: daRelayAdmissionRetained}
	return nil
}

func (p *daCompleteCommitPlan) projectCompleteTotals(capacity daCompleteCapacityPlan) error {
	s := p.projected
	if p.mismatch {
		var err error
		p.sharedBytes, err = checkedAddUint64(s.stagedBytes, s.completeBytes)
		return err
	}
	if p.capacityRejected {
		return nil
	}
	var err error
	s.completeBytes, err = checkedApplyUint64Delta(capacity.sharedBytes, s.stagedBytes, 0)
	s.completeCount, s.pinnedPayloadBytes = capacity.completeCount, capacity.payloadBytes
	return err
}

func sameDACompleteRecord(a, b daRelaySetRecord) bool {
	type header struct {
		id                                     [32]byte
		state                                  daRelaySetState
		revision, received, payload, wire, ttl uint64
		intrinsic                              daCompleteCapacitySet
		replaceable, chunks                    bool
	}
	x := header{a.daID, a.state, a.revision, a.receivedTime, a.payloadBytes, a.wireBytes, a.ttlBlocksRemaining, a.completeIntrinsic, a.replaceableChunks == nil, a.chunks == nil}
	y := header{b.daID, b.state, b.revision, b.receivedTime, b.payloadBytes, b.wireBytes, b.ttlBlocksRemaining, b.completeIntrinsic, b.replaceableChunks == nil, b.chunks == nil}
	if x != y || !maps.Equal(a.replaceableChunks, b.replaceableChunks) || !sameOwnerReadyCommit(a.commit, b.commit) {
		return false
	}
	return maps.EqualFunc(a.chunks, b.chunks, sameDACompleteChunk)
}

// sameOwnerReadyChunk compares payload bytes; this also preserves nil versus empty.
func sameDACompleteChunk(a, b daRelayChunk) bool {
	return (a.payload == nil) == (b.payload == nil) && sameOwnerReadyChunk(a, b)
}

func (s *DARelayState) sameDACompleteBaseline(base *DARelayState, owner *PendingOutpointOwner) bool {
	if s.mempool != base.mempool || s.mempool.pendingOutpoints != owner || s.caps != base.caps {
		return false
	}
	a := [8]uint64{s.stagedBytes, s.completeBytes, s.completeCount, s.orphanBytes, s.orphanCommitOverheadBytes, s.pinnedPayloadBytes, s.records, s.nextReceivedTime}
	b := [8]uint64{base.stagedBytes, base.completeBytes, base.completeCount, base.orphanBytes, base.orphanCommitOverheadBytes, base.pinnedPayloadBytes, base.records, base.nextReceivedTime}
	return a == b && maps.Equal(s.orphanBytesByPeerQuotaKey, base.orphanBytesByPeerQuotaKey) &&
		maps.Equal(s.orphanBytesByDAID, base.orphanBytesByDAID) && maps.Equal(s.locators, base.locators) && maps.EqualFunc(s.sets, base.sets, sameDACompleteRecord)
}

func (s *DARelayState) applyDACompleteCommit(admission *DAAdmission, p *daCompleteCommitPlan) (daRelayAdmissionOutcome, bool, error) {
	if p == nil {
		return daRelayAdmissionOutcome{}, false, errDARelayImageIncompatible
	}
	type binding struct {
		relay     *DARelayState
		admission *DAAdmission
	}
	if (binding{p.relay, p.admission}) != (binding{s, admission}) || admission.guard.state.Load() != daAdmissionOpen {
		return daRelayAdmissionOutcome{}, false, errDARelayImageIncompatible
	}
	p.admission = nil
	if p.duplicate != nil {
		return *p.duplicate, false, nil
	}
	s.mu.Lock()
	if duplicate, ok := s.duplicateDANonReplayLocked(p.source.candidate); ok {
		s.mu.Unlock()
		return duplicate, false, nil
	}
	if p.mismatch && !sameDACompleteRecord(s.sets[p.source.prior.daID], p.source.prior) {
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, daCompleteStaleError()
	}
	return s.reserveDACompleteCommit(admission, p)
}

func (s *DARelayState) reserveDACompleteCommit(admission *DAAdmission, p *daCompleteCommitPlan) (daRelayAdmissionOutcome, bool, error) {
	if !admission.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting) {
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, errDARelayImageIncompatible
	}
	defer admission.guard.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
	commit, failure, failed := reservePreparedDAAdmissionCommit(p.owner)
	if failed {
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, selectRelayDisposition(txAdmitFromPendingOutpointError(&failure), relayDispositionForOwnerError(&failure))
	}
	if !s.sameDACompleteBaseline(p.source.publicationBase, p.source.owner) {
		commit.Abort()
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, daCompleteStaleError()
	}
	if failure, failed = p.source.owner.validateDAAdmissionVictimsLocked(p.original, commit.candidate); failed {
		commit.Abort()
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, selectRelayDisposition(txAdmitFromPendingOutpointError(&failure), relayDispositionForOwnerError(&failure))
	}
	return s.finishDACompleteCommit(p, commit)
}

func daCompleteStaleError() error {
	return selectRelayDisposition(txAdmitUnavailable("retained DA record moved while this admission was planned"), RelayAdmissionUnavailable)
}

func (p *daCompleteCommitPlan) mismatchRefusal() error {
	if !p.mismatch {
		return nil
	}
	if p.sharedBytes > p.projected.caps.stagedBytes {
		return errDARelayOrphanPoolCapExceeded
	}
	if p.projected.orphanCommitOverheadBytes > p.projected.caps.orphanCommitOverheadBytes {
		return errDARelayOrphanCommitCapExceeded
	}
	if p.source.nextReceivedTime == math.MaxUint64 {
		return errDARelayArithmeticOverflow
	}
	return nil
}

func (s *DARelayState) finishDACompleteCommit(p *daCompleteCommitPlan, commit *DACommit) (daRelayAdmissionOutcome, bool, error) {
	err := p.mismatchRefusal()
	if err != nil || p.capacityRejected {
		commit.Abort()
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, p.capacityRejected, err
	}
	p.member.token = commit.candidate
	s.publishDACompleteLocked(p)
	commit.Commit()
	s.mu.Unlock()
	return p.outcome, false, nil
}

func (s *DARelayState) publishDACompleteLocked(p *daCompleteCommitPlan) {
	projected := p.projected
	s.nextReceivedTime = projected.nextReceivedTime
	s.stagedBytes = projected.stagedBytes
	s.completeBytes = projected.completeBytes
	s.completeCount = projected.completeCount
	s.orphanBytes = projected.orphanBytes
	s.orphanBytesByPeerQuotaKey = projected.orphanBytesByPeerQuotaKey
	s.orphanBytesByDAID = projected.orphanBytesByDAID
	s.orphanCommitOverheadBytes = projected.orphanCommitOverheadBytes
	s.pinnedPayloadBytes = projected.pinnedPayloadBytes
	s.sets = projected.sets
	s.locators = projected.locators
	s.records = projected.records
	for _, id := range p.prefetch {
		s.prefetch.releaseSet(id)
	}
}
