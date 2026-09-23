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
	result           daCompletePreparation
	next             daRelaySetRecord
	placement        daRelayRecordPlacement
	capacity         daCompleteCapacityPlan
	retire           []daRelayLocatorRow
	sequence         uint64
	owner            *daPreparedAdmissionCommit
	original         []DAAdmissionVictim
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
	if result.prepared != nil {
		prepared := *result.prepared
		prepared.image.next = prepared.image.next.cloneOwnerReady()
		prepared.pruned = slices.Clone(prepared.pruned)
		p.result.prepared = &prepared
	} else {
		mismatch := *result.mismatch
		mismatch.image.next = mismatch.image.next.cloneOwnerReady()
		mismatch.removed = slices.Clone(mismatch.removed)
		p.result.mismatch = &mismatch
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
		if result.prepared.source == nil || result.prepared.image.next.state != daRelayStateCompleteSet || result.prepared.image.next.completeIntrinsic != result.prepared.set || result.prepared.set.id != result.prepared.source.prior.daID {
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
	if source == nil || s.mempool == nil {
		return false
	}
	if s.mempool != source.mempool || source.owner != a.guard.owner || s.mempool.pendingOutpoints != source.owner {
		return false
	}
	m, snapshot := source.candidate.member, a.snapshot
	return [2][32]byte{m.member.txid, m.member.wtxid} == [2][32]byte{snapshot.TxID, snapshot.WTxID} &&
		m.member.fee == snapshot.Fee && sameDACompleteAdmissionBuffers(m, snapshot)
}

func sameDACompleteAdmissionBuffers(m daRelayOwnerReadyMember, snapshot DAAdmissionSnapshot) bool {
	return bytes.Equal(m.txBytes, snapshot.TxBytes) && slices.Equal(m.member.inputs, snapshot.Inputs)
}

func (p *daCompleteCommitPlan) prepareEffects(s *DARelayState, admission *DAAdmission) error {
	var victims []DAAdmissionVictim
	var err error
	if p.result.prepared != nil {
		input, err := s.capacityInput(p.source, p.result.prepared.set)
		if err != nil {
			return err
		}
		p.capacity, err = planDACompleteCapacity(input)
		if err != nil {
			return err
		}
		p.capacityRejected = !p.capacity.accepted
		p.next = p.result.prepared.image.next.cloneOwnerReady()
		if !p.capacityRejected {
			victims = slices.Clone(p.result.prepared.pruned)
		}
	} else {
		p.mismatch = true
		p.next = p.result.mismatch.image.next.cloneOwnerReady()
		victims = slices.Clone(p.result.mismatch.removed)
	}
	if err := p.checkCompletingMember(); err != nil {
		return err
	}
	p.prepareOriginalClaims(s)
	p.prepareRetire(s, &victims)
	p.owner, err = prepareDAAdmissionCommit(admission, victims)
	if err != nil {
		return selectRelayDisposition(txAdmitFromPendingOutpointError(err), relayDispositionForOwnerError(err))
	}
	return p.projectCompletion(s)
}

func (p *daCompleteCommitPlan) checkCompletingMember() error {
	if err := p.checkDACompleteNextShape(); err != nil {
		return err
	}
	p.member = p.next.commit.member
	raw := p.next.commit.txBytes
	if p.source.candidate.member.locator.kind == daRelayLocatorChunk {
		chunk, present := p.next.chunks[p.source.candidate.member.locator.chunkIndex]
		if !present || chunk.member == nil {
			return errDARelayImageIncompatible
		}
		p.member, raw = chunk.member, chunk.txBytes
	}
	if !sameOwnerReadyMember(p.member, &p.source.candidate.member.member) || !bytes.Equal(raw, p.source.candidate.member.txBytes) {
		return errDARelayImageIncompatible
	}
	return nil
}

func (p *daCompleteCommitPlan) checkDACompleteNextShape() error {
	if p.next.commit.member == nil || p.next.daID != p.source.prior.daID {
		return errDARelayImageIncompatible
	}
	if p.mismatch {
		return nil
	}
	if len(p.next.chunks) != int(p.next.commit.chunkCount) {
		return errDARelayImageIncompatible
	}
	type chunkShape struct {
		present bool
		index   uint16
		inRange bool
	}
	for index, chunk := range p.next.chunks {
		if (chunkShape{chunk.member != nil, chunk.chunkIndex, index < p.next.commit.chunkCount}) != (chunkShape{true, index, true}) {
			return errDARelayImageIncompatible
		}
	}
	return nil
}

func (p *daCompleteCommitPlan) prepareOriginalClaims(s *DARelayState) {
	p.original = daCompleteRecordClaims(p.source.prior)
	if p.mismatch {
		return
	}
	for _, record := range s.sets {
		if record.state == daRelayStateCompleteSet {
			p.original = append(p.original, daCompleteRecordClaims(record)...)
		}
	}
}

func (p *daCompleteCommitPlan) prepareRetire(s *DARelayState, victims *[]DAAdmissionVictim) {
	for _, resident := range p.capacity.victims {
		record := s.sets[resident]
		*victims = append(*victims, daCompleteRecordClaims(record)...)
		p.retire = append(p.retire, record.locatorRows()...)
	}
	nextRows := p.next.locatorRows()
	for _, row := range p.source.prior.locatorRows() {
		if row.txid != p.source.candidate.member.member.txid {
			found := false
			for _, next := range nextRows {
				found = found || row == next
			}
			if !found {
				p.retire = append(p.retire, row)
			}
		}
	}
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

func (p *daCompleteCommitPlan) projectCompletion(s *DARelayState) error {
	old := p.source.prior
	// The existing counter projector only sees A/B. C totals come from its planner.
	billed := daRelaySetRecord{daID: old.daID}
	if p.mismatch {
		billed = p.next
	}
	caps := s.caps
	caps.stagedBytes, caps.orphanPoolBytes, caps.orphanPoolPerDAIDBytes = math.MaxUint64, math.MaxUint64, math.MaxUint64
	caps.orphanPoolPerPeerBytes, caps.orphanCommitOverheadBytes = math.MaxUint64, math.MaxUint64
	accounting, err := s.projectDARecordImageCountersLocked(daRelayRecordImage{daID: old.daID, next: billed}, old, caps)
	if err != nil {
		return err
	}
	p.placement = accounting
	if p.capacityRejected {
		return nil
	}
	p.next.revision, err = checkedAddUint64(s.records, 1)
	if err != nil {
		return err
	}
	p.next.receivedTime = old.receivedTime
	p.outcome = daRelayAdmissionOutcome{daID: old.daID, disposition: daRelayAdmissionRetained}
	if p.mismatch {
		p.sharedBytes, err = checkedAddUint64(accounting.stagedBytes, s.completeBytes)
		return err
	} else {
		_, err = checkedApplyUint64Delta(p.capacity.sharedBytes, accounting.stagedBytes, 0)
	}
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

func (s *DARelayState) sameDACompleteTarget(source *daCompleteSnapshot) bool {
	if s.mempool == nil {
		return false
	}
	type binding struct {
		mempool *Mempool
		owner   *PendingOutpointOwner
	}
	if (binding{s.mempool, s.mempool.pendingOutpoints}) != (binding{source.mempool, source.owner}) {
		return false
	}
	if !sameDACompleteRecord(s.sets[source.prior.daID], source.prior) {
		return false
	}
	for txid, locator := range source.locators {
		if s.locators[txid] != locator {
			return false
		}
	}
	count := 0
	for _, locator := range s.locators {
		if locator.daID == source.prior.daID {
			count++
		}
	}
	return count == len(source.locators)
}

func (s *DARelayState) applyDACompleteCommit(admission *DAAdmission, p *daCompleteCommitPlan) (daRelayAdmissionOutcome, bool, error) {
	if !p.readyForDACompleteApply(s, admission) {
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
	if err := s.checkDACompleteFinalTarget(p); err != nil {
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, err
	}
	if err := p.prepareEffects(s, admission); err != nil {
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, err
	}
	if err := s.preflightDACompleteCommit(p); err != nil {
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, err
	}
	return s.reserveDACompleteCommit(admission, p)
}

func (p *daCompleteCommitPlan) readyForDACompleteApply(s *DARelayState, admission *DAAdmission) bool {
	if p == nil {
		return false
	}
	type binding struct {
		relay     *DARelayState
		admission *DAAdmission
	}
	return (binding{p.relay, p.admission}) == (binding{s, admission}) && admission.guard.state.Load() == daAdmissionOpen
}

func (s *DARelayState) checkDACompleteFinalTarget(p *daCompleteCommitPlan) error {
	if !s.sameDACompleteTarget(p.source) {
		return daCompleteStaleError()
	}
	if p.source.prior.receivedTime > s.nextReceivedTime || p.source.prior.revision > s.records {
		return errDARelayImageIncompatible
	}
	if p.result.prepared != nil && s.nextReceivedTime == math.MaxUint64 {
		return errDARelayArithmeticOverflow
	}
	return nil
}

func (s *DARelayState) preflightDACompleteCommit(p *daCompleteCommitPlan) error {
	if ([4]bool{s.sets != nil, s.locators != nil, s.orphanBytesByDAID != nil, s.orphanBytesByPeerQuotaKey != nil}) != ([4]bool{true, true, true, true}) {
		return errDARelayImageIncompatible
	}
	value := s.sets[p.source.prior.daID]
	s.sets[p.source.prior.daID] = value
	if value, ok := s.orphanBytesByDAID[p.source.prior.daID]; ok {
		s.orphanBytesByDAID[p.source.prior.daID] = value
	}
	for key := range p.placement.peerBytes {
		if value, ok := s.orphanBytesByPeerQuotaKey[key]; ok {
			s.orphanBytesByPeerQuotaKey[key] = value
		}
	}
	txid := p.source.candidate.member.member.txid
	if _, present := s.locators[txid]; present {
		return errDARelayImageIncompatible
	}
	s.locators[txid] = p.source.candidate.member.locator
	return nil
}

func (s *DARelayState) discardDACompleteProvisional(p *daCompleteCommitPlan) {
	delete(s.locators, p.source.candidate.member.member.txid)
}

func (s *DARelayState) reserveDACompleteCommit(admission *DAAdmission, p *daCompleteCommitPlan) (daRelayAdmissionOutcome, bool, error) {
	if !admission.guard.state.CompareAndSwap(daAdmissionOpen, daAdmissionAttempting) {
		s.discardDACompleteProvisional(p)
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, errDARelayImageIncompatible
	}
	defer admission.guard.state.CompareAndSwap(daAdmissionAttempting, daAdmissionResolved)
	commit, failure, failed := reservePreparedDAAdmissionCommit(p.owner)
	if failed {
		s.discardDACompleteProvisional(p)
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, selectRelayDisposition(txAdmitFromPendingOutpointError(&failure), relayDispositionForOwnerError(&failure))
	}
	if failure, failed = p.source.owner.validateDAAdmissionVictimsLocked(p.original, commit.candidate); failed {
		commit.Abort()
		s.discardDACompleteProvisional(p)
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, false, selectRelayDisposition(txAdmitFromPendingOutpointError(&failure), relayDispositionForOwnerError(&failure))
	}
	return s.finishDACompleteCommit(p, commit)
}

func daCompleteStaleError() error {
	return selectRelayDisposition(txAdmitUnavailable("retained DA record moved while this admission was planned"), RelayAdmissionUnavailable)
}

func (p *daCompleteCommitPlan) mismatchRefusal(s *DARelayState) error {
	if !p.mismatch {
		return nil
	}
	if p.sharedBytes > s.caps.stagedBytes {
		return errDARelayOrphanPoolCapExceeded
	}
	if p.placement.commitBytes > s.caps.orphanCommitOverheadBytes {
		return errDARelayOrphanCommitCapExceeded
	}
	if s.nextReceivedTime == math.MaxUint64 {
		return errDARelayArithmeticOverflow
	}
	return nil
}

func (s *DARelayState) finishDACompleteCommit(p *daCompleteCommitPlan, commit *DACommit) (daRelayAdmissionOutcome, bool, error) {
	err := p.mismatchRefusal(s)
	if err != nil || p.capacityRejected {
		commit.Abort()
		s.discardDACompleteProvisional(p)
		s.mu.Unlock()
		return daRelayAdmissionOutcome{}, p.capacityRejected, err
	}
	p.sequence = s.nextReceivedTime + 1
	p.member.token = commit.candidate
	s.publishDACompleteLocked(p)
	commit.Commit()
	s.mu.Unlock()
	return p.outcome, false, nil
}

func (s *DARelayState) publishDACompleteLocked(p *daCompleteCommitPlan) {
	for _, row := range p.retire {
		delete(s.locators, row.txid)
	}
	for _, id := range p.capacity.victims {
		delete(s.sets, id)
		s.prefetch.releaseSet(id)
	}
	s.sets[p.source.prior.daID] = p.next
	s.nextReceivedTime = p.sequence
	s.records = p.next.revision
	s.stagedBytes = p.placement.stagedBytes
	s.orphanBytes = p.placement.orphanBytes
	s.orphanCommitOverheadBytes = p.placement.commitBytes
	s.applyProjectedPeerBytes(p.placement.peerBytes)
	s.applyProjectedDAIDBytes(p.source.prior.daID, p.placement.daBytes)
	if !p.mismatch {
		s.completeBytes = p.capacity.sharedBytes - p.placement.stagedBytes
		s.completeCount = p.capacity.completeCount
		s.pinnedPayloadBytes = p.capacity.payloadBytes
	}
	s.prefetch.releaseSet(p.source.prior.daID)
}
