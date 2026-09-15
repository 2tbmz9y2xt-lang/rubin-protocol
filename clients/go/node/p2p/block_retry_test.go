package p2p

import (
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// blockRetryConn records every write, write deadline and Close under mu. writeHook, when set,
// replaces the default write (forward to Conn, or succeed when Conn is nil); closeHook runs on
// every Close and closed is closed by the first one. The existing scriptedConn is unsynchronized
// and counts no Close, and the waiter writes from its own goroutine.
type blockRetryConn struct {
	net.Conn
	mu        sync.Mutex
	writes    [][]byte
	deadlines []time.Time
	closes    int
	closed    chan struct{}
	writeHook func([]byte) (int, error)
	closeHook func()
}

func newBlockRetryConn(inner net.Conn) *blockRetryConn {
	return &blockRetryConn{Conn: inner, closed: make(chan struct{})}
}

func (c *blockRetryConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, bytes.Clone(b))
	hook := c.writeHook
	c.mu.Unlock()
	switch {
	case hook != nil:
		return hook(b)
	case c.Conn != nil:
		return c.Conn.Write(b)
	}
	return len(b), nil
}

func (c *blockRetryConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	if c.Conn != nil {
		return c.Conn.SetWriteDeadline(deadline)
	}
	return nil
}

func (c *blockRetryConn) Close() error {
	c.mu.Lock()
	c.closes++
	first, hook := c.closes == 1, c.closeHook
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	if first {
		close(c.closed)
	}
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

// snapshot returns every byte written so far and the Close count.
func (c *blockRetryConn) snapshot() ([]byte, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.writes, nil), c.closes
}

// blockRetryService installs the cancellable context and the cancel function Close invokes, and
// a zero write deadline so the bounded stall budget is 15 s.
func blockRetryService(t *testing.T, s *Service) *Service {
	t.Helper()
	if s == nil {
		s = newTestHarness(t, 0, "127.0.0.1:0", nil).service
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.cfg.PeerRuntimeConfig.WriteDeadline = 0
	return s
}

func blockRetryPeer(s *Service, addr string) (*peer, *blockRetryConn) {
	conn := newBlockRetryConn(nil)
	return &peer{conn: conn, service: s, state: node.PeerState{Addr: addr}}, conn
}

func blockRetryReleased() chan struct{} {
	notify := make(chan struct{})
	close(notify)
	return notify
}

// blockRetryFrame is the expected getdata frame built from literals: the harness devnet magic,
// the NUL-padded command, u32le(33), the first four bytes of SHA3-256(payload), then 0x01 || hash.
func blockRetryFrame(hash [32]byte) []byte {
	payload := append([]byte{0x01}, hash[:]...)
	sum := sha3.Sum256(payload)
	frame := append([]byte("RBDV"), "getdata\x00\x00\x00\x00\x00"...)
	frame = binary.LittleEndian.AppendUint32(frame, 33)
	frame = append(frame, sum[:4]...)
	return append(frame, payload...)
}

func blockRetrySlotOf(p *peer) *blockRetrySlot {
	p.retryMu.Lock()
	defer p.retryMu.Unlock()
	return p.retry
}

func armBlockRetrySlot(t *testing.T, p *peer, hash [32]byte, notify <-chan struct{}, receiveStart time.Time) *blockRetrySlot {
	t.Helper()
	requireEqual(t, p.armBlockRetry(hash, notify, receiveStart), blockRetryArmed, "arm result")
	slot := blockRetrySlotOf(p)
	require(t, slot != nil, "no slot right after an armed result")
	return slot
}

func waitBlockRetryDone(t *testing.T, slot *blockRetrySlot, label string) {
	t.Helper()
	select {
	case <-slot.done:
	case <-time.After(lifecycleWatchdog):
		t.Fatalf("%s: the waiter did not exit within %s", label, lifecycleWatchdog)
	}
}

// waitBlockRetryAbsent waits for the waiter's exit where the slot pointer cannot be captured
// first: the exit clears the slot, closes done and releases the lease in one retryMu section.
func waitBlockRetryAbsent(t *testing.T, p *peer, label string) {
	t.Helper()
	waitUntil(t, func() bool { return blockRetrySlotOf(p) == nil }, label)
}

func waitBlockRetrySent(t *testing.T, p *peer) {
	t.Helper()
	waitUntil(t, func() bool {
		p.retryMu.Lock()
		defer p.retryMu.Unlock()
		return p.retry != nil && p.retry.phase == blockRetrySent
	}, "phase SENT")
}

// requireBlockRetrySlot asserts the peer still holds slot with the values it was armed with.
func requireBlockRetrySlot(t *testing.T, p *peer, slot *blockRetrySlot, hash [32]byte, deadline time.Time, phase blockRetryPhase, label string) {
	t.Helper()
	p.retryMu.Lock()
	current, gotHash, gotDeadline, gotPhase := p.retry, slot.hash, slot.deadline, slot.phase
	p.retryMu.Unlock()
	require(t, current == slot && gotHash == hash && gotDeadline.Equal(deadline) && gotPhase == phase,
		"%s: slot same=%v hash=%x deadline=%v phase=%d, want hash=%x deadline=%v phase=%d", label, current == slot, gotHash, gotDeadline, gotPhase, hash, deadline, phase)
}

// requireNoBlockRetryEffect asserts the slot is gone and left no frame, Close, LastError or ban.
func requireNoBlockRetryEffect(t *testing.T, p *peer, conn *blockRetryConn, label string) {
	t.Helper()
	written, closes := conn.snapshot()
	state := p.snapshotState()
	require(t, len(written) == 0 && closes == 0 && state.LastError == "" && state.BanScore == 0 && blockRetrySlotOf(p) == nil,
		"%s: written=%d closes=%d lastError=%q ban=%d slot=%v", label, len(written), closes, state.LastError, state.BanScore, blockRetrySlotOf(p) != nil)
}

// parkBlockRetryWrite arms hash with a released notification and holds the waiter inside its
// first frame write until release is called; the write then succeeds.
func parkBlockRetryWrite(t *testing.T, p *peer, conn *blockRetryConn, hash [32]byte) (*blockRetrySlot, func()) {
	t.Helper()
	entered, gate := make(chan struct{}), make(chan struct{})
	var once sync.Once
	conn.writeHook = func(b []byte) (int, error) {
		once.Do(func() { close(entered) })
		<-gate
		return len(b), nil
	}
	slot := armBlockRetrySlot(t, p, hash, blockRetryReleased(), time.Now())
	requireChannelClosed(t, entered, "the waiter's gated write")
	return slot, func() { close(gate) }
}

func requireCallReturns(t *testing.T, label string, call func()) {
	t.Helper()
	done := make(chan error, 1)
	go func() { call(); done <- nil }()
	requireReturned(t, done, label)
}

func TestBlockRetryArm(t *testing.T) {
	hash, other := [32]byte{0xa1}, [32]byte{0xb2}
	t.Run("armed_exact_deadline", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		notify := make(chan struct{})
		receiveStart := time.Now()
		slot := armBlockRetrySlot(t, p, hash, notify, receiveStart)
		require(t, slot.notify == notify, "slot notify is not the armed channel")
		requireBlockRetrySlot(t, p, slot, hash, receiveStart.Add(30*time.Second), blockRetryWaiting, "armed slot")
		written, _ := conn.snapshot()
		requireEqual(t, len(written), 0, "bytes written by arm")
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("nil_notification", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		requireEqual(t, p.armBlockRetry(hash, nil, time.Now()), blockRetryNoNotification, "nil notify on an OPEN Service")
		require(t, blockRetrySlotOf(p) == nil, "a nil notify created a slot")
		slot, release := parkBlockRetryWrite(t, p, conn, hash)
		requireEqual(t, p.armBlockRetry(other, nil, time.Now()), blockRetryNoNotification, "nil notify while a slot is armed")
		requireBlockRetrySlot(t, p, slot, hash, slot.deadline, blockRetryWaiting, "slot after the nil notify")
		release()
		waitBlockRetrySent(t, p)
		requireReturned(t, lifecycleClose(p.service), "Close")
		waitBlockRetryDone(t, slot, "Close")
		requireEqual(t, p.armBlockRetry(hash, nil, time.Now()), blockRetryNoNotification, "nil notify on a closed Service")
	})
	rearmRefused := func(t *testing.T, second [32]byte) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		notify := make(chan struct{})
		receiveStart := time.Now()
		slot := armBlockRetrySlot(t, p, hash, notify, receiveStart)
		for _, phase := range []blockRetryPhase{blockRetryWaiting, blockRetrySent} {
			if phase == blockRetrySent {
				close(notify)
				waitBlockRetrySent(t, p)
			}
			requireEqual(t, p.armBlockRetry(second, make(chan struct{}), receiveStart.Add(-time.Second)), blockRetryAlreadyArmed, "second arm")
			requireBlockRetrySlot(t, p, slot, hash, receiveStart.Add(30*time.Second), phase, "slot after the second arm")
			require(t, slot.notify == notify, "the second arm replaced notify")
		}
		written, _ := conn.snapshot()
		require(t, bytes.Equal(written, blockRetryFrame(hash)), "written=%x, want exactly one frame %x", written, blockRetryFrame(hash))
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose")
		requireReturned(t, lifecycleClose(p.service), "Close after the refused arms")
	}
	t.Run("already_armed_same_hash", func(t *testing.T) { rearmRefused(t, hash) })
	t.Run("already_armed_other_hash", func(t *testing.T) { rearmRefused(t, other) })
	t.Run("service_closed", func(t *testing.T) {
		s := newTestHarness(t, 0, "127.0.0.1:0", nil).service
		p, conn := blockRetryPeer(s, "block-retry-peer")
		refused := func(label string) {
			t.Helper()
			var got blockRetryArm
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("%s: arm panicked: %v", label, recovered)
					}
				}()
				got = p.armBlockRetry(hash, make(chan struct{}), time.Now())
			}()
			requireEqual(t, got, blockRetryServiceClosed, label)
			require(t, blockRetrySlotOf(p) == nil, "%s: a refused arm left a slot", label)
		}
		refused("nil Service context")
		s.ctx = context.Background()
		refused("live Service context without its cancel function")
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		s.ctx, s.cancel = cancelled, cancel
		refused("Service context cancelled without Close")
		blockRetryService(t, s)
		slot, release := parkBlockRetryWrite(t, p, conn, hash)
		s.cancel()
		requireEqual(t, p.armBlockRetry(other, make(chan struct{}), time.Now()), blockRetryServiceClosed, "arm on a cancelled Service context while a slot is armed")
		requireBlockRetrySlot(t, p, slot, hash, slot.deadline, blockRetryWaiting, "slot after the refused arm")
		release()
		waitBlockRetryDone(t, slot, "the released waiter")
		requireReturned(t, lifecycleClose(s), "Close")
		refused("arm after Close returned")
		requireReturned(t, lifecycleClose(s), "Close after every refused arm")
	})
	t.Run("concurrent_arm_single_slot", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		notify, start := make(chan struct{}), make(chan struct{})
		results := make(chan blockRetryArm, 16)
		var arms sync.WaitGroup
		for i := range 16 {
			arms.Go(func() {
				<-start
				results <- p.armBlockRetry([32]byte{byte(i)}, notify, time.Now())
			})
		}
		close(start)
		arms.Wait()
		close(results)
		counts := map[blockRetryArm]int{}
		for result := range results {
			counts[result]++
		}
		require(t, counts[blockRetryArmed] == 1 && counts[blockRetryAlreadyArmed] == 15, "arm results=%v, want 1 armed and 15 already armed", counts)
		slot := blockRetrySlotOf(p)
		close(notify)
		waitBlockRetrySent(t, p)
		written, _ := conn.snapshot()
		require(t, bytes.Equal(written, blockRetryFrame(slot.hash)), "written=%x, want one frame for the armed hash", written)
		requireReturned(t, lifecycleClose(p.service), "Close")
		waitBlockRetryDone(t, slot, "Close")
	})
	t.Run("rearm_after_completion", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		rearm := func(label string, id byte, notify <-chan struct{}, receiveStart time.Time) *blockRetrySlot {
			t.Helper()
			slot := armBlockRetrySlot(t, p, [32]byte{id}, notify, receiveStart)
			require(t, slot.hash == [32]byte{id} && slot.deadline.Equal(receiveStart.Add(30*time.Second)), "%s: hash=%x deadline=%v, want %x and %v", label, slot.hash, slot.deadline, [32]byte{id}, receiveStart.Add(30*time.Second))
			return slot
		}
		slot := rearm("first arm", 1, make(chan struct{}), time.Now())
		p.disposeBlockRetry([32]byte{1})
		waitBlockRetryDone(t, slot, "dispose completion")
		slot = rearm("arm after dispose", 2, blockRetryReleased(), time.Now().Add(-29*time.Second))
		waitBlockRetryDone(t, slot, "deadline completion after the send")
		slot = rearm("arm after the SENT deadline", 3, make(chan struct{}), time.Now().Add(-29*time.Second))
		waitBlockRetryDone(t, slot, "timeout completion before release")
		failing, gate := errors.New("block retry rearm write failure"), make(chan struct{})
		conn.writeHook = func([]byte) (int, error) { <-gate; return 0, failing }
		slot = rearm("arm after the timeout", 4, blockRetryReleased(), time.Now())
		close(gate)
		waitBlockRetryDone(t, slot, "send failure completion")
		requireEqual(t, p.snapshotState().LastError, failing.Error(), "LastError after the send failure")
		slot = rearm("arm after the send failure", 5, make(chan struct{}), time.Now())
		p.disposeBlockRetry([32]byte{5})
		waitBlockRetryDone(t, slot, "final dispose")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
}

func TestBlockRetrySend(t *testing.T) {
	hash := [32]byte{0xc3}
	releaseSends := func(t *testing.T, before bool) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		notify := make(chan struct{})
		if before {
			close(notify)
		}
		receiveStart := time.Now()
		slot := armBlockRetrySlot(t, p, hash, notify, receiveStart)
		if !before {
			close(notify)
		}
		waitBlockRetrySent(t, p)
		written, closes := conn.snapshot()
		require(t, bytes.Equal(written, blockRetryFrame(hash)), "written=%x, want %x", written, blockRetryFrame(hash))
		requireBlockRetrySlot(t, p, slot, hash, receiveStart.Add(30*time.Second), blockRetrySent, "SENT slot")
		requireEqual(t, closes, 0, "connection closes after a successful send")
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose")
		requireReturned(t, lifecycleClose(p.service), "Close")
	}
	t.Run("release_sends_one_getdata", func(t *testing.T) { releaseSends(t, false) })
	t.Run("release_before_arm", func(t *testing.T) { releaseSends(t, true) })
	t.Run("write_deadline_is_original", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		receiveStart := time.Now().Add(-20 * time.Second) // slot deadline 10 s away, before the 15 s frame and stall budgets
		slot := armBlockRetrySlot(t, p, hash, blockRetryReleased(), receiveStart)
		waitBlockRetrySent(t, p)
		conn.mu.Lock()
		deadlines := append([]time.Time(nil), conn.deadlines...)
		conn.mu.Unlock()
		require(t, len(deadlines) == 2, "write deadlines=%v, want one per header and payload chunk", deadlines)
		for i, deadline := range deadlines {
			require(t, deadline.Equal(receiveStart.Add(30*time.Second)), "write deadline %d=%v, want receive start plus 30 s %v", i, deadline, receiveStart.Add(30*time.Second))
		}
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("contended_writer_past_deadline", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		p.writeMu.Lock()
		receiveStart := time.Now().Add(-28 * time.Second)
		slot := armBlockRetrySlot(t, p, hash, blockRetryReleased(), receiveStart)
		waitUntil(t, func() bool { return time.Now().After(receiveStart.Add(30 * time.Second)) }, "the slot deadline passing")
		p.writeMu.Unlock()
		waitBlockRetryDone(t, slot, "contended writer past the deadline")
		requireNoBlockRetryEffect(t, p, conn, "contended writer past the deadline")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("send_failure_closes_peer", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		sentinel := errors.New("block retry sentinel write failure")
		phaseInWrite, writerAtClose := blockRetryPhase(0xff), "not probed" // the assertions below fail unless both probes ran
		conn.writeHook = func([]byte) (int, error) {
			p.retryMu.Lock()
			phaseInWrite = p.retry.phase
			p.retryMu.Unlock()
			return 0, sentinel
		}
		conn.closeHook = func() {
			writerAtClose = "held"
			if p.writeMu.TryLock() {
				p.writeMu.Unlock()
				writerAtClose = "free"
			}
		}
		requireEqual(t, p.armBlockRetry(hash, blockRetryReleased(), time.Now()), blockRetryArmed, "arm result")
		waitBlockRetryAbsent(t, p, "the waiter ending after the send failure")
		written, closes := conn.snapshot()
		state := p.snapshotState()
		require(t, state.LastError == sentinel.Error() && state.BanScore == 0 && closes == 1 && len(written) == 24 && blockRetrySlotOf(p) == nil,
			"lastError=%q ban=%d closes=%d written=%d slot=%v, want the sentinel, no ban, one Close, one header attempt, no slot", state.LastError, state.BanScore, closes, len(written), blockRetrySlotOf(p) != nil)
		requireEqual(t, phaseInWrite, blockRetryWaiting, "phase observed inside the failing write")
		requireEqual(t, writerAtClose, "free", "writer mutex state probed from the connection Close")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("late_complete_write_is_failure", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		conn.writeHook = func(b []byte) (int, error) {
			if len(b) == 33 {
				return len(b), os.ErrDeadlineExceeded
			}
			return len(b), nil
		}
		requireEqual(t, p.armBlockRetry(hash, blockRetryReleased(), time.Now()), blockRetryArmed, "arm result")
		waitBlockRetryAbsent(t, p, "the waiter ending after the late complete write")
		written, closes := conn.snapshot()
		state := p.snapshotState()
		require(t, bytes.Equal(written, blockRetryFrame(hash)) && state.LastError == os.ErrDeadlineExceeded.Error() && state.BanScore == 0 && closes == 1 && blockRetrySlotOf(p) == nil,
			"written=%d lastError=%q ban=%d closes=%d slot=%v, want the whole frame, the deadline error, no ban, one Close, no slot", len(written), state.LastError, state.BanScore, closes, blockRetrySlotOf(p) != nil)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("terminal_at_wake", func(t *testing.T) {
		h := newTestHarness(t, 1, "127.0.0.1:0", nil)
		latchDAHarness(t, h, newTestHarness(t, 2, "127.0.0.1:0", nil))
		p, conn := blockRetryPeer(blockRetryService(t, h.service), "block-retry-peer")
		notify := make(chan struct{})
		slot := armBlockRetrySlot(t, p, hash, notify, time.Now())
		close(notify)
		waitUntil(t, func() bool { // the waiter's first observable decision: its exit or a frame
			written, _ := conn.snapshot()
			select {
			case <-slot.done:
				return true
			default:
				return len(written) > 0
			}
		}, "the waiter deciding after the release")
		written, _ := conn.snapshot()
		require(t, len(written) == 0, "a frame was written with the terminal latch set: %x", written)
		waitBlockRetryDone(t, slot, "terminal latch at wake")
		requireNoBlockRetryEffect(t, p, conn, "terminal latch at wake")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("cancelled_at_wake", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		notify := make(chan struct{})
		slot := armBlockRetrySlot(t, p, hash, notify, time.Now())
		p.service.cancel()
		waitBlockRetryDone(t, slot, "Service context cancellation with the notification open")
		close(notify)
		requireNoBlockRetryEffect(t, p, conn, "cancelled at wake")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("repeated_release_no_second_send", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		notify := blockRetryReleased()
		slot := armBlockRetrySlot(t, p, hash, notify, time.Now())
		waitBlockRetrySent(t, p)
		requireEqual(t, p.armBlockRetry(hash, notify, time.Now()), blockRetryAlreadyArmed, "repeated arm while SENT")
		written, _ := conn.snapshot()
		require(t, bytes.Equal(written, blockRetryFrame(hash)), "written=%x, want exactly one frame", written)
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
}

func TestBlockRetryDispose(t *testing.T) {
	hash, other := [32]byte{0xd4}, [32]byte{0xe5}
	t.Run("dispose_waiting", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		notify := make(chan struct{})
		slot := armBlockRetrySlot(t, p, hash, notify, time.Now())
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose with the notification open")
		close(notify)
		requireNoBlockRetryEffect(t, p, conn, "dispose while WAITING")
		p.writeMu.Lock() // released notification, contended writer: the cancellation has to end the waiter without the writer
		slot = armBlockRetrySlot(t, p, hash, blockRetryReleased(), time.Now())
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose with the writer contended")
		p.writeMu.Unlock()
		requireNoBlockRetryEffect(t, p, conn, "dispose with the writer contended")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("dispose_sent", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		slot := armBlockRetrySlot(t, p, hash, blockRetryReleased(), time.Now())
		waitBlockRetrySent(t, p)
		requireCallReturns(t, "dispose", func() { p.disposeBlockRetry(hash) })
		waitBlockRetryDone(t, slot, "dispose while SENT")
		written, closes := conn.snapshot()
		require(t, bytes.Equal(written, blockRetryFrame(hash)) && closes == 0 && blockRetrySlotOf(p) == nil, "written=%x closes=%d slot=%v, want one frame, no Close, no slot", written, closes, blockRetrySlotOf(p) != nil)
		slot = armBlockRetrySlot(t, p, hash, make(chan struct{}), time.Now())
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose of the later arm")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("dispose_other_hash", func(t *testing.T) {
		p, _ := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		notify := make(chan struct{})
		slot := armBlockRetrySlot(t, p, hash, notify, time.Now())
		for _, phase := range []blockRetryPhase{blockRetryWaiting, blockRetrySent} {
			if phase == blockRetrySent {
				close(notify)
				waitBlockRetrySent(t, p)
			}
			p.disposeBlockRetry(other)
			select { // negative window: a wrongly cancelled waiter removes the slot inside it
			case <-slot.done:
			case <-time.After(lifecycleSettle):
			}
			requireBlockRetrySlot(t, p, slot, hash, slot.deadline, phase, "slot after dispose with another hash")
		}
		p.disposeBlockRetry(hash)
		waitBlockRetryDone(t, slot, "dispose")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("dispose_absent", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		requireCallReturns(t, "dispose with no slot", func() { p.disposeBlockRetry(hash) })
		requireNoBlockRetryEffect(t, p, conn, "dispose with no slot")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("dispose_races_release", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		frame := blockRetryFrame(hash)
		for i := range 64 {
			before, _ := conn.snapshot()
			notify, start := make(chan struct{}), make(chan struct{})
			slot := armBlockRetrySlot(t, p, hash, notify, time.Now())
			released := make(chan struct{})
			go func() { <-start; close(notify); close(released) }()
			close(start)
			p.disposeBlockRetry(hash)
			<-released
			waitBlockRetryDone(t, slot, "dispose racing the release")
			written, _ := conn.snapshot()
			sent := written[len(before):]
			require(t, (len(sent) == 0 || bytes.Equal(sent, frame)) && blockRetrySlotOf(p) == nil, "iteration %d: sent=%x slot=%v, want zero or one frame and no slot", i, sent, blockRetrySlotOf(p) != nil)
		}
		// The one-send history the race above almost never reaches: the dispose lands after the writer recheck,
		// while the waiter is inside its write, so that write completes and the waiter then exits without a second send.
		before, _ := conn.snapshot()
		slot, release := parkBlockRetryWrite(t, p, conn, hash)
		p.disposeBlockRetry(hash)
		release()
		waitBlockRetryDone(t, slot, "dispose during the write")
		written, _ := conn.snapshot()
		require(t, bytes.Equal(written[len(before):], frame) && blockRetrySlotOf(p) == nil, "dispose during the write: sent=%x slot=%v, want exactly one frame and no slot", written[len(before):], blockRetrySlotOf(p) != nil)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
}

func TestBlockRetryDeadline(t *testing.T) {
	hash := [32]byte{0xf6}
	t.Run("deadline_before_release", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		requireEqual(t, p.armBlockRetry(hash, make(chan struct{}), time.Now().Add(-31*time.Second)), blockRetryArmed, "arm result")
		waitBlockRetryAbsent(t, p, "the waiter ending at the deadline")
		requireNoBlockRetryEffect(t, p, conn, "deadline before release")
		// Released notification with the deadline already passed and a free writer: either wake case ends
		// without a frame, the notify case through the expiry recheck after acquiring the writer.
		requireEqual(t, p.armBlockRetry(hash, blockRetryReleased(), time.Now().Add(-31*time.Second)), blockRetryArmed, "arm result")
		waitBlockRetryAbsent(t, p, "the waiter ending with the deadline already passed")
		requireNoBlockRetryEffect(t, p, conn, "release with the deadline already passed")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("deadline_ends_sent", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		slot := armBlockRetrySlot(t, p, hash, blockRetryReleased(), time.Now().Add(-28*time.Second)) // deadline 2 s away, room for the send before it
		waitBlockRetryDone(t, slot, "SENT slot at its deadline")
		written, closes := conn.snapshot()
		state := p.snapshotState()
		require(t, bytes.Equal(written, blockRetryFrame(hash)) && closes == 0 && state.LastError == "" && state.BanScore == 0 && blockRetrySlotOf(p) == nil,
			"written=%x closes=%d lastError=%q ban=%d slot=%v, want one frame and no other effect", written, closes, state.LastError, state.BanScore, blockRetrySlotOf(p) != nil)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
}

func TestBlockRetryPeerExit(t *testing.T) {
	hash := [32]byte{0x17}
	t.Run("finish_joins_parked_writer", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		parked, gate := make(chan struct{}), make(chan struct{})
		failure := errors.New("block retry write ended by finish")
		conn.writeHook = func([]byte) (int, error) {
			close(parked)
			<-conn.closed
			<-gate
			return 0, failure
		}
		slot := armBlockRetrySlot(t, p, hash, blockRetryReleased(), time.Now())
		requireChannelClosed(t, parked, "the waiter's write")
		finished := make(chan error, 1)
		go func() { p.finishBlockRetry(); finished <- nil }()
		select {
		case <-conn.closed:
		case <-time.After(lifecycleWatchdog):
			t.Fatalf("finishBlockRetry did not close the connection within %s", lifecycleWatchdog)
		}
		requireStillBlocked(t, finished, "finishBlockRetry")
		close(gate)
		requireReturned(t, finished, "finishBlockRetry")
		select {
		case <-slot.done:
		default:
			t.Fatal("finishBlockRetry returned before done was closed")
		}
		state := p.snapshotState()
		require(t, blockRetrySlotOf(p) == nil && state.LastError == failure.Error() && state.BanScore == 0, "slot=%v lastError=%q ban=%d, want no slot, the write failure, no ban", blockRetrySlotOf(p) != nil, state.LastError, state.BanScore)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("finish_absent", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		requireCallReturns(t, "finishBlockRetry with no slot", p.finishBlockRetry)
		requireNoBlockRetryEffect(t, p, conn, "finish with no slot")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("finish_idempotent", func(t *testing.T) {
		p, conn := blockRetryPeer(blockRetryService(t, nil), "block-retry-peer")
		slot := armBlockRetrySlot(t, p, hash, make(chan struct{}), time.Now())
		requireCallReturns(t, "first finishBlockRetry", p.finishBlockRetry)
		waitBlockRetryDone(t, slot, "first finishBlockRetry")
		requireCallReturns(t, "second finishBlockRetry", p.finishBlockRetry)
		written, closes := conn.snapshot()
		require(t, closes == 1 && len(written) == 0 && blockRetrySlotOf(p) == nil, "closes=%d written=%d slot=%v, want one Close from the first finish only", closes, len(written), blockRetrySlotOf(p) != nil)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
}
