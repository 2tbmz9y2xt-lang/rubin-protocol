package p2p

import (
	"context"
	"time"
)

// blockRetryDeadline is the life of a block re-request slot, measured from the receive
// start of the refused frame; nothing observed later extends it.
const blockRetryDeadline = 30 * time.Second

// blockRetryArm is the result of armBlockRetry.
type blockRetryArm uint8

const (
	blockRetryArmed blockRetryArm = iota + 1
	blockRetryAlreadyArmed
	blockRetryServiceClosed
	blockRetryNoNotification
)

// blockRetryPhase is the published state of an armed slot.
type blockRetryPhase uint8

const (
	blockRetryWaiting blockRetryPhase = iota
	blockRetrySent
)

// blockRetrySlot is the one dormant block re-request a peer may hold. Every field except
// phase is fixed at arm; phase is written only by the slot's waiter, under peer.retryMu.
// The slot retains no block bytes, lease, reader or budget state.
type blockRetrySlot struct {
	hash     [32]byte
	notify   <-chan struct{}
	deadline time.Time
	phase    blockRetryPhase
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
}

// armBlockRetry arms the peer's re-request slot for hash, given the capacity release
// notification observed at the refusal and the refused frame's receive start (a time.Now
// reading). It returns the first refusal in this order:
//   - notify is nil: blockRetryNoNotification, before any lease, context or slot check.
//   - the Service refuses a work lease, or its context is nil, already cancelled or has no
//     cancel function beside it: blockRetryServiceClosed; a lease taken by the call is
//     released before return and an existing slot is left unchanged.
//   - a slot exists in either phase: blockRetryAlreadyArmed; its hash, notify, deadline,
//     phase and waiter are unchanged and the lease taken by the call is released.
//
// Otherwise it publishes one WAITING slot whose deadline is receiveStart plus
// blockRetryDeadline, transfers the lease to one started waiter and returns
// blockRetryArmed. Arm sends nothing and changes no peer state.
func (p *peer) armBlockRetry(hash [32]byte, notify <-chan struct{}, receiveStart time.Time) blockRetryArm {
	if notify == nil {
		return blockRetryNoNotification
	}
	s := p.service
	if !s.acquireWork() {
		return blockRetryServiceClosed
	}
	s.peersMu.RLock()
	parent, stop := s.ctx, s.cancel
	s.peersMu.RUnlock()
	if parent == nil || stop == nil || parent.Err() != nil {
		s.releaseWork()
		return blockRetryServiceClosed
	}
	p.retryMu.Lock()
	if p.retry != nil {
		p.retryMu.Unlock()
		s.releaseWork()
		return blockRetryAlreadyArmed
	}
	ctx, cancel := context.WithCancel(parent)
	slot := &blockRetrySlot{hash: hash, notify: notify, deadline: receiveStart.Add(blockRetryDeadline), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	p.retry = slot
	p.retryMu.Unlock()
	go p.runBlockRetry(slot, time.NewTimer(time.Until(slot.deadline)))
	return blockRetryArmed
}

// runBlockRetry is the slot's only waiter. After notify closes it sends at most one getdata
// (sendBlockRetry); it ends on the slot context, on the deadline timer, or after a send that
// did not happen or failed. On exit it clears peer.retry, closes done and releases the
// transferred lease inside one retryMu section, so no retryMu holder sees the slot cleared
// while its lease is still held, and Service Close never returns before done is closed.
func (p *peer) runBlockRetry(slot *blockRetrySlot, timer *time.Timer) {
	defer func() {
		timer.Stop()
		slot.cancel()
		p.retryMu.Lock()
		p.retry = nil
		close(slot.done)
		p.service.releaseWork()
		p.retryMu.Unlock()
	}()
	select {
	case <-slot.ctx.Done():
		return
	case <-timer.C:
		return
	case <-slot.notify:
	}
	if !p.sendBlockRetry(slot) {
		return
	}
	// notify is closed by now, so only cancellation or the same deadline ends a SENT slot.
	select {
	case <-slot.ctx.Done():
	case <-timer.C:
	}
}

// sendBlockRetry runs the send path after an observed release and reports whether the
// getdata frame was written and SENT published. It writes nothing when the slot context is
// cancelled, the engine terminal latch is set, or the bounded writer acquisition is cancelled
// or reaches the slot deadline; the connection stays open on those paths. Any frame write
// error is a send failure: the writer mutex is released first, then the error is recorded
// with setLastError and only this connection is closed.
func (p *peer) sendBlockRetry(slot *blockRetrySlot) bool {
	if slot.ctx.Err() != nil || p.service.cfg.SyncEngine.TerminalFaulted() {
		return false
	}
	if acquired, err := p.lockCompactFallbackWrite(slot.ctx, slot.deadline); err != nil || !acquired {
		return false
	}
	body := append([]byte{MSG_BLOCK}, slot.hash[:]...)
	// The slot deadline can only shorten the frame's own budget (RUBIN_L1_P2P_AUX.md Section 2.1).
	err := p.writePostHandshakeFrame(messageGetData, body, earlierDeadline(slot.deadline, time.Now().Add(frameBudgetDuration(uint64(len(body))))))
	p.writeMu.Unlock()
	if err != nil {
		p.setLastError(err.Error())
		_ = p.conn.Close()
		return false
	}
	p.retryMu.Lock()
	slot.phase = blockRetrySent
	p.retryMu.Unlock()
	return true
}

// disposeBlockRetry cancels the slot when its hash equals hash; the waiter then exits without
// a further send and removes the slot itself. Any other hash, or no slot, has no effect. It
// never waits for the waiter and never touches the connection. Call it only from the owning
// peer's own frame-processing sequence: a disposition then always follows the refusal that
// armed the slot, and the hash is the only binding.
func (p *peer) disposeBlockRetry(hash [32]byte) {
	p.retryMu.Lock()
	defer p.retryMu.Unlock()
	if p.retry != nil && p.retry.hash == hash {
		p.retry.cancel()
	}
}

// finishBlockRetry joins the slot's waiter. With no slot it returns at once; otherwise it
// cancels the slot, closes the peer connection so a write in progress fails instead of
// outliving the join, and returns only after done is closed and the waiter's lease is
// released. A repeated call after the join finds no slot and returns at once. handleConn runs
// it after the peer's frame reader has returned; arming a slot after it is outside the
// supported path.
func (p *peer) finishBlockRetry() {
	p.retryMu.Lock()
	slot := p.retry
	p.retryMu.Unlock()
	if slot == nil {
		return
	}
	slot.cancel()
	_ = p.conn.Close()
	<-slot.done
	p.retryMu.Lock() // barrier: the waiter releases its lease in the retryMu section that closed done
	p.retryMu.Unlock()
}
