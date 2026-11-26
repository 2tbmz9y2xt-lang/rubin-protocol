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
	transport *peer
	lastID    uint64
}

// imageSourcesLive checks the requested entries before allocating the candidate source set.
func (req *imageRequester) imageSourcesLive(ids []string, peers map[string]*peer) bool {
	req.mu.Lock()
	defer req.mu.Unlock()
	for _, id := range ids {
		if p := peers[id]; p == nil || p.imageRetired {
			return false
		}
	}
	return true
}

func checkImageSourcesLocked(sources map[string]*peer) error {
	for _, p := range sources {
		if p.imageRetired {
			return errImageSourceSet
		}
	}
	return nil
}

// ImageResult identifies the admitted query of a local assignment outcome.
type ImageResult struct {
	Query consensus.UTXOImageQuery
}

type imageOutcome struct {
	query consensus.UTXOImageQuery
	end   error
	ready bool
}

// Receive takes one completed outcome for expectedStart in admission order, or waits without a Service lease
// while that start has a current assignment or a pending write result (RUBIN_L1_P2P_AUX.md Section 7.5).
func (r *ImageRound) Receive(ctx context.Context, expectedStart [36]byte) (ImageResult, error) {
	round := *r
	s := round.service
	for {
		result, err, wake := round.receiveOnce(ctx, expectedStart)
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
func (r *ImageRound) receiveOnce(ctx context.Context, start [36]byte) (ImageResult, error, <-chan struct{}) {
	s := r.service
	if !s.acquireWork() {
		return ImageResult{}, errServiceClosed, nil
	}
	defer s.releaseWork()
	if ctx == nil {
		return ImageResult{}, errImageNilContext, nil
	}
	req := s.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if r.closed {
		return ImageResult{}, errImageRoundClosed, nil
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

func (r *ImageRound) takeOrWaitLocked(ctx context.Context, start [36]byte) (ImageResult, error, <-chan struct{}) {
	queue := r.outcomes[start]
	if len(queue) != 0 && queue[0].ready {
		outcome := queue[0]
		r.deleteOutcomeLocked(start, queue, 0)
		return ImageResult{Query: outcome.query}, outcome.end, nil
	}
	current := r.service.imageRequester.current[imageKey{r.anchor, start}]
	if len(queue) == 0 && (current == nil || current.round.imageRoundUsage != r.imageRoundUsage) {
		return ImageResult{}, errImageNoAssignment, nil
	}
	if err := ctx.Err(); err != nil {
		return ImageResult{}, err, nil
	}
	if r.wake == nil {
		r.wake = make(chan struct{})
	}
	return ImageResult{}, nil, r.wake
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
	inst.recordOutcomeLocked()
	inst.round.wakeImageWaitersLocked()
}

// detachImageInstanceLocked releases logical ownership and stops the directly owned timer.
func (req *imageRequester) detachImageInstanceLocked(inst *imageInstance, end error) {
	inst.timer.Stop()
	inst.retired, inst.end = true, end
	delete(req.current, imageKey{inst.round.anchor, inst.query.StartKey})
	inst.round.release(inst.session, unitCurrentAssignments, 1)
	inst.ref.Store(nil)
}

// recordOutcomeLocked appends in admission order because the next assignment for a start
// cannot be admitted until the current one retires.
func (inst *imageInstance) recordOutcomeLocked() {
	r := &inst.round
	if r.closed || inst.sendPhase == imageBeforeWrite {
		return
	}
	if r.outcomes == nil {
		r.outcomes = make(map[[36]byte][]*imageOutcome)
	}
	outcome := &imageOutcome{query: inst.query, end: inst.end, ready: inst.sendPhase == imageSent}
	start := inst.query.StartKey
	r.outcomes[start] = append(r.outcomes[start], outcome)
	if !outcome.ready {
		inst.staged = outcome
	}
}

// finishSend resolves an authorized write's provisional outcome and releases any pending bytes still held.
func (r *ImageRound) finishSend(inst *imageInstance, sent bool) {
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if inst.sendPhase == imageWriting {
		inst.sendPhase = imageBeforeWrite
		if sent {
			inst.sendPhase = imageSent
		}
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
		inst.staged.ready = true
	} else {
		start := inst.query.StartKey
		queue := r.outcomes[start]
		if i := slices.Index(queue, inst.staged); i >= 0 {
			r.deleteOutcomeLocked(start, queue, i)
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
	round.outcomes = nil
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
	if p.imageRetired {
		return
	}
	session := p.imageSession
	if session == nil {
		p.imageRetired = true
		return
	}
	req.detachImageSessionLocked(session)
	req.retireImageOwnerLocked(s, errImageDisconnected, func(inst *imageInstance) bool {
		return inst.session == session
	})
}

// retireImageOwnerLocked uses one clock sample for the matching instances and prefers an already due end.
func (req *imageRequester) retireImageOwnerLocked(s *Service, reason error, matches func(*imageInstance) bool) {
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
}

func (req *imageRequester) detachImageSessionLocked(session *imageSession) {
	session.transport.imageRetired = true
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
}
