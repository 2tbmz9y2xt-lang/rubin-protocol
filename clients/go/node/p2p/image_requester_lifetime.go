package p2p

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var (
	errImageRoundClosed  = errors.New("image requester: round is closed")
	errImageDisconnected = errors.New("image requester: source disconnected")
	errImageNoAssignment = errors.New("image requester: no assignment for start")
	errImageRoundMode    = errors.New("image requester: wrong round mode")
)

// imageSession is the registration identity captured by rounds and assignments.
// The requester mutex guards the allocator and the detachable transport.
type imageSession struct {
	transport   *peer
	lastID      uint64
	currentByID map[uint64]*imageInstance
}

// indexCurrentLocked binds the admitted ID to its exact registration and instance.
func (s *imageSession) indexCurrentLocked(inst *imageInstance) {
	if s.currentByID == nil {
		s.currentByID = make(map[uint64]*imageInstance)
	}
	s.currentByID[inst.query.RequestID] = inst
}

// unindexCurrentLocked removes only the attachment owned by the retiring instance.
func (s *imageSession) unindexCurrentLocked(inst *imageInstance) {
	id := inst.query.RequestID
	if s.currentByID[id] != inst {
		return
	}
	delete(s.currentByID, id)
	if len(s.currentByID) == 0 {
		s.currentByID = nil
	}
}

func checkImageSourcesLocked(sources map[string]*peer) error {
	for _, p := range sources {
		if p.imageRetired.Load() {
			return errImageSourceSet
		}
	}
	return nil
}

// ImageResult contains the admitted query and its whole verified range, probe attribution or source diagnostic.
// A local assignment end supplies only Query (RUBIN_L1_P2P_AUX.md Sections 7.5, 7.7 and 7.8).
type ImageResult struct {
	Query       consensus.UTXOImageQuery
	Range       *consensus.UTXOImageRange
	Attribution *ImageAttribution
	Diagnostic  string
}

type imageOutcome struct {
	result      ImageResult
	end         error
	ready       bool
	holderBytes uint64
	bodyKey     imageQualificationKey
}

// Receive takes one completed outcome for expectedStart in admission order, or waits without a Service lease
// while that start has a current assignment or a pending write result (RUBIN_L1_P2P_AUX.md Section 7.5).
func (r *ImageRound) Receive(ctx context.Context, expectedStart [36]byte) (ImageResult, error) {
	round := *r
	s := round.service
	for {
		result, wake, err := round.receiveOnce(ctx, expectedStart)
		if wake == nil {
			return result, err
		}
		select {
		case <-wake:
		case <-ctx.Done():
		case <-s.imageRequester.drain:
		}
	}
}

// receiveOnce holds a lease only through its nonwaiting decision, even if DRAINING is published after entry.
func (r *ImageRound) receiveOnce(ctx context.Context, start [36]byte) (ImageResult, <-chan struct{}, error) {
	s := r.service
	if !s.acquireWork() {
		return ImageResult{}, nil, errServiceClosed
	}
	defer s.releaseWork()
	if ctx == nil {
		return ImageResult{}, nil, errImageNilContext
	}
	req := s.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if r.closed {
		return ImageResult{}, nil, errImageRoundClosed
	}
	req.receiveEndPassLocked(s.cfg.Now())
	return r.takeOrWaitLocked(ctx, start)
}

// receiveEndPassLocked records observed ends without calling external context stop functions.
func (req *imageRequester) receiveEndPassLocked(now time.Time) {
	for _, inst := range req.current {
		if end := inst.endAt(now); end != nil {
			req.completeImageEndLocked(inst, end)
		}
	}
}

func (r *ImageRound) takeOrWaitLocked(ctx context.Context, start [36]byte) (ImageResult, <-chan struct{}, error) {
	queue := r.outcomes[start]
	if len(queue) != 0 && queue[0].ready {
		outcome := queue[0]
		result, end := outcome.result, outcome.end
		r.deleteOutcomeLocked(start, queue, 0)
		r.service.imageRequester.discardImageOutcomeLocked(outcome)
		return result, nil, end
	}
	current := r.service.imageRequester.current[imageKey{r.anchor, start}]
	if len(queue) == 0 && (current == nil || current.round.imageRoundUsage != r.imageRoundUsage) {
		return ImageResult{}, nil, errImageNoAssignment
	}
	if err := ctx.Err(); err != nil {
		return ImageResult{}, nil, err
	}
	if r.wake == nil {
		r.wake = make(chan struct{})
	}
	return ImageResult{}, r.wake, nil
}

// wakeImageWaitersLocked releases the round's passive waiters for another decision.
func (r *ImageRound) wakeImageWaitersLocked() {
	if r.wake != nil {
		close(r.wake)
		r.wake = nil
	}
}

// deleteOutcomeLocked removes one record and drops its reference from the queue.
func (r *ImageRound) deleteOutcomeLocked(start [36]byte, queue []*imageOutcome, index int) {
	if len(queue) == 1 {
		delete(r.outcomes, start)
		return
	}
	if index == 0 {
		queue[0] = nil
		r.outcomes[start] = queue[1:]
		return
	}
	r.outcomes[start] = slices.Delete(queue, index, index+1)
}

// completeImageEndLocked records the end, revokes its appliers and retains the local outcome when write-authorized.
func (req *imageRequester) completeImageEndLocked(inst *imageInstance, end error) {
	req.detachImageInstanceLocked(inst, end)
	if !inst.round.closed && (inst.sendPhase == imageSent || inst.sendPhase == imageWriting) {
		inst.recordOutcomeLocked(&imageOutcome{end: end})
	}
	inst.round.wakeImageWaitersLocked()
}

// detachImageInstanceLocked releases logical ownership and stops the owned end signals.
func (req *imageRequester) detachImageInstanceLocked(inst *imageInstance, end error) {
	inst.timer.Stop()
	inst.retired, inst.end = true, end
	delete(req.current, imageKey{inst.round.anchor, inst.query.StartKey})
	inst.session.unindexCurrentLocked(inst)
	inst.round.release(inst.session, unitCurrentAssignments, 1)
	inst.revokeEndNotifications()
}

// recordOutcomeLocked appends in admission order because the next assignment for a start
// cannot be admitted until the current one retires.
func (inst *imageInstance) recordOutcomeLocked(outcome *imageOutcome) {
	r := &inst.round
	if r.outcomes == nil {
		r.outcomes = make(map[[36]byte][]*imageOutcome)
	}
	outcome.result.Query = inst.query
	outcome.ready = inst.sendPhase == imageSent || inst.sendPhase == imageUnwound
	if outcome.result.Attribution != nil {
		outcome.result.Attribution.generation.record(outcome.ready)
	}
	start := inst.query.StartKey
	r.outcomes[start] = append(r.outcomes[start], outcome)
	if !outcome.ready {
		inst.staged = outcome
	}
}

// finishSend resolves an authorized write's provisional outcome and releases any pending bytes still held.
func (r *ImageRound) finishSend(inst *imageInstance, returned bool, sendErr error) {
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	sent := returned && sendErr == nil
	switch {
	case !returned:
		inst.sendPhase = imageUnwound
	case sent:
		inst.sendPhase = imageSent
	}
	if inst.staged != nil {
		r.resolveStagedLocked(inst, sent)
		inst.staged = nil
	}
	inst.releasePendingLocked()
}

// resolveStagedLocked makes the record ready on a normal nil result and removes only that record on unwind.
func (r *ImageRound) resolveStagedLocked(inst *imageInstance, sent bool) {
	if r.closed {
		return
	}
	if sent {
		inst.staged.publish()
	} else {
		start := inst.query.StartKey
		queue := r.outcomes[start]
		if i := slices.Index(queue, inst.staged); i >= 0 {
			r.deleteOutcomeLocked(start, queue, i)
			r.service.imageRequester.discardImageOutcomeLocked(inst.staged)
		}
	}
	r.wakeImageWaitersLocked()
}

// Close ends the shared round, drops its untaken outcomes and wakes its waiters.
func (r *ImageRound) Close() {
	round := *r
	s := round.service
	if !s.acquireWork() {
		return
	}
	defer s.releaseWork()
	req := s.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if round.closed {
		return
	}
	round.closed = true
	round.qualified = nil
	round.discardImageOutcomesLocked()
	req.retireImageOwnerLocked(s, errImageRoundClosed, func(inst *imageInstance) bool {
		return inst.round.imageRoundUsage == round.imageRoundUsage
	})
	round.wakeImageWaitersLocked()
}

// retireImagePeer ends assignments and drops transport and allocator ownership before peer cleanup.
func (s *Service) retireImagePeer(p *peer) {
	req := s.imageRequester
	if req == nil {
		return
	}
	req.mu.Lock()
	defer req.mu.Unlock()
	if p.imageRetired.Load() {
		return
	}
	session := p.imageSession
	if session == nil {
		p.imageRetired.Store(true)
		return
	}
	req.detachImageSessionLocked(session)
	req.retireImageOwnerLocked(s, errImageDisconnected, func(inst *imageInstance) bool {
		return inst.session == session
	})
}

// retireImageOwnerLocked uses one clock sample for the matching instances and prefers an already due end.
// An interrupted observation retires the remaining matching instances with reason.
func (req *imageRequester) retireImageOwnerLocked(s *Service, reason error, matches func(*imageInstance) bool) {
	finished := false
	defer func() {
		if finished {
			return
		}
		for _, inst := range req.current {
			if matches(inst) {
				req.completeImageEndLocked(inst, reason)
			}
		}
	}()
	var now time.Time
	sampled := false
	for _, inst := range req.current {
		if !matches(inst) {
			continue
		}
		if !sampled {
			now, sampled = s.cfg.Now(), true
		}
		end := inst.endAt(now)
		if end == nil {
			end = reason
		}
		req.completeImageEndLocked(inst, end)
	}
	finished = true
}

func (req *imageRequester) detachImageSessionLocked(session *imageSession) {
	session.transport.imageRetired.Store(true)
	session.transport, session.lastID = nil, 0
	delete(req.sessions, session)
}

// finishImageRequester drops remaining registrations and revokes end appliers after leased work joins.
func (s *Service) finishImageRequester() {
	req := s.imageRequester
	if req == nil {
		return
	}
	req.mu.Lock()
	defer req.mu.Unlock()
	for _, inst := range req.current {
		req.detachImageInstanceLocked(inst, errServiceClosed)
	}
	for session := range req.sessions {
		req.detachImageSessionLocked(session)
	}
	for outcome := range req.held {
		req.discardImageOutcomeLocked(outcome)
	}
}
