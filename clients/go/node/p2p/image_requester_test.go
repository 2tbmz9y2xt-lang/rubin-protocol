package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// imageTestClock is a controlled ServiceConfig.Now that is safe for concurrent reads and counts
// them. onRead, when set, runs once on the next read; its result is stored as the clock's time,
// so that read and the later reads return it until the clock moves again, and hookRead is the
// number of that read. After followRealTime,
// each read first moves the clock to base plus the real time elapsed since realFrom. A move to
// an earlier time fails the test.
type imageTestClock struct {
	t        *testing.T
	mu       sync.Mutex
	now      time.Time
	reads    int
	hookRead int
	onRead   func(time.Time) time.Time
	base     time.Time
	realFrom time.Time
}

func (c *imageTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if !c.realFrom.IsZero() {
		c.moveLocked(c.base.Add(time.Since(c.realFrom)))
	}
	if hook := c.onRead; hook != nil {
		c.onRead, c.hookRead = nil, c.reads
		c.moveLocked(hook(c.now))
	}
	return c.now
}

func (c *imageTestClock) moveLocked(next time.Time) {
	if next.Before(c.now) {
		c.t.Errorf("controlled clock moved back from %v to %v", c.now, next)
	}
	c.now = next
}

func (c *imageTestClock) set(now time.Time) {
	c.mu.Lock()
	c.moveLocked(now)
	c.mu.Unlock()
}

func (c *imageTestClock) add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.moveLocked(c.now.Add(d))
	return c.now
}

func (c *imageTestClock) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func (c *imageTestClock) onNextRead(hook func(time.Time) time.Time) {
	c.mu.Lock()
	c.onRead = hook
	c.mu.Unlock()
}

// followRealTime makes the later reads first move the clock to its time at this call plus the
// real time elapsed since from, which carries a monotonic reading.
func (c *imageTestClock) followRealTime(from time.Time) {
	c.mu.Lock()
	c.base, c.realFrom = c.now, from
	c.mu.Unlock()
}

// cancelOnRead makes the next read call cancel before it returns, leaving the clock.
func (c *imageTestClock) cancelOnRead(cancel func()) {
	c.onNextRead(func(now time.Time) time.Time {
		cancel()
		return now
	})
}

// awaitReadsAfterHook waits for the n-th clock read after the last hook's read, then takes the
// requester mutex, which admission, the pre-write decision, the ctx callbacks and the deadline
// timer hold across their clock read and what follows it, and
// checks that the clock was read exactly n times after the hook's read.
func (f *imageTestFixture) awaitReadsAfterHook(t *testing.T, n int, label string) {
	t.Helper()
	f.clock.mu.Lock()
	hookRead := f.clock.hookRead
	f.clock.mu.Unlock()
	waitUntil(t, func() bool { return f.clock.readCount() >= hookRead+n }, label+": clock reads after the hook")
	req := f.lockRequester()
	reads := f.clock.readCount()
	req.mu.Unlock()
	requireEqual(t, reads, hookRead+n, label+": clock reads after the hook")
}

// jumpOnRead makes the next read move the clock to now and call cancel before it returns.
func (c *imageTestClock) jumpOnRead(now time.Time, cancel func()) {
	c.onNextRead(func(time.Time) time.Time {
		cancel()
		return now
	})
}

// applyImageEndRead returns a channel that the first later read made inside applyImageEnd, which
// the ctx callbacks and the deadline timer run, closes; the reads, until then, leave the clock
// unchanged.
func (c *imageTestClock) applyImageEndRead() <-chan struct{} {
	read := make(chan struct{})
	var hook func(time.Time) time.Time
	hook = func(now time.Time) time.Time {
		if imageCalledFrom(".(*Service).applyImageEnd") {
			close(read)
			return now
		}
		c.onRead = hook
		return now
	}
	c.onNextRead(hook)
	return read
}

// imageWire is the write side of one session connection: a write is recorded and succeeds; with
// a stall armed, that one write first blocks until the stall receives its result and, given an
// error, fails with it unrecorded; with a panic armed, the next write panics with that value
// before it records a byte. A write that starts after the connection was closed, or whose
// stall releases it with no error after that, fails with net.ErrClosed unrecorded.
type imageWire struct {
	mu        sync.Mutex
	sent      []byte
	stall     *imageStall
	panicNext any
	closed    <-chan struct{}
}

type imageStall struct {
	entered chan struct{}
	release chan error
}

func (w *imageWire) write(b []byte) (int, error) {
	if w.isClosed() {
		return 0, net.ErrClosed
	}
	w.mu.Lock()
	stall, value := w.stall, w.panicNext
	w.stall, w.panicNext = nil, nil
	w.mu.Unlock()
	if value != nil {
		panic(value)
	}
	if stall != nil {
		close(stall.entered)
		if err := <-stall.release; err != nil {
			return 0, err
		}
		if w.isClosed() {
			return 0, net.ErrClosed
		}
	}
	w.mu.Lock()
	w.sent = append(w.sent, b...)
	w.mu.Unlock()
	return len(b), nil
}

func (w *imageWire) isClosed() bool {
	select {
	case <-w.closed:
		return true
	default:
		return false
	}
}

func (w *imageWire) armStall() *imageStall {
	stall := &imageStall{entered: make(chan struct{}), release: make(chan error, 1)}
	w.mu.Lock()
	w.stall = stall
	w.mu.Unlock()
	return stall
}

func (w *imageWire) armPanic(value any) {
	w.mu.Lock()
	w.panicNext = value
	w.mu.Unlock()
}

func (w *imageWire) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.sent)
}

type imageTestFixture struct {
	t     *testing.T
	h     *testHarness
	s     *Service
	clock *imageTestClock
	peers []*peer
	conns []*blockRetryConn
	wires []*imageWire
	ids   []string
}

var imageTestAnchor = ImageAnchor{Height: 7, BlockHash: [32]byte{0xb1}, Root: [32]byte{0x52}}

const (
	imageTestByteLimit = 150905
	imageMaxWall       = math.MaxInt64 - 62135596800
)

func newImageTestFixture(t *testing.T, sessions int) *imageTestFixture {
	t.Helper()
	return newImageTestFixtureAt(t, sessions, time.Unix(1_800_000_000, 0))
}

// newImageTestFixtureAt starts the controlled clock at start, which also fixes its clock domain.
func newImageTestFixtureAt(t *testing.T, sessions int, start time.Time) *imageTestFixture {
	t.Helper()
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	f := &imageTestFixture{t: t, h: h, s: h.service, clock: &imageTestClock{t: t, now: start}}
	f.s.cfg.Now = f.clock.Now
	f.s.cfg.PeerRuntimeConfig.WriteDeadline = 0
	for i := 0; i < sessions; i++ {
		f.addSession(t, fmt.Sprintf("image-peer-%d:19111", i), fmt.Sprintf("192.0.2.%d:9", 40+i))
	}
	return f
}

// addSession registers a handshaken connection with logical address addr whose socket reports
// endpoint, counts Close and writes through an imageWire.
func (f *imageTestFixture) addSession(t *testing.T, addr, endpoint string) int {
	t.Helper()
	p := daRelayTestPeer(f.h, addr, endpoint)
	conn := newBlockRetryConn(&scriptedConn{remote: stubAddr(endpoint)})
	wire := &imageWire{closed: conn.closed}
	conn.writeHook = wire.write
	p.conn = conn
	must(t, callWithin(t, "register "+addr, func() error { return f.s.registerPeer(p) }), "register "+addr)
	f.peers, f.conns, f.wires, f.ids = append(f.peers, p), append(f.conns, conn), append(f.wires, wire), append(f.ids, addr)
	return len(f.peers) - 1
}

func imageTestUnits(value uint64) ImageUnits {
	return ImageUnits{value, value, value, value, value, value, value, value, value, value, value, value}
}

func imageTestLimits() ImageLimits {
	return ImageLimits{
		PerPeer: imageTestUnits(1 << 20), Global: imageTestUnits(1 << 20),
		AttemptLifetime: 10 * time.Second, RoundLifetime: time.Hour, Backoff: time.Second,
	}
}

func (f *imageTestFixture) config(limits ImageLimits, sources ...int) ImageRoundConfig {
	config := ImageRoundConfig{Anchor: imageTestAnchor, Limits: limits}
	for _, index := range sources {
		config.SourceIDs = append(config.SourceIDs, f.ids[index])
	}
	return config
}

type imageBegin struct {
	round *ImageRound
	err   error
}

// begin calls BeginImageRound and fails the test when it has not returned within
// lifecycleWatchdog.
func (f *imageTestFixture) begin(ctx context.Context, config ImageRoundConfig) (*ImageRound, error) {
	f.t.Helper()
	got := callWithin(f.t, "BeginImageRound", func() imageBegin {
		round, err := f.s.BeginImageRound(ctx, config)
		return imageBegin{round, err}
	})
	return got.round, got.err
}

func (f *imageTestFixture) roundCtx(t *testing.T, ctx context.Context, limits ImageLimits, sources ...int) *ImageRound {
	t.Helper()
	round, err := f.begin(ctx, f.config(limits, sources...))
	must(t, err, "BeginImageRound")
	return round
}

func (f *imageTestFixture) round(t *testing.T, limits ImageLimits, sources ...int) *ImageRound {
	t.Helper()
	return f.roundCtx(t, context.Background(), limits, sources...)
}

func imageStart(b byte) [36]byte { return [36]byte{b} }

func expectedImageQuery(id uint64, start byte) consensus.UTXOImageQuery {
	return consensus.UTXOImageQuery{RequestID: id, Height: 7, BlockHash: [32]byte{0xb1}, Root: [32]byte{0x52}, StartKey: imageStart(start), ByteLimit: imageTestByteLimit}
}

type imageResult struct {
	q   consensus.UTXOImageQuery
	err error
}

// receiveWithin returns what done delivers, or false when it delivers nothing within bound.
func receiveWithin[T any](done <-chan T, bound time.Duration) (T, bool) {
	select {
	case v := <-done:
		return v, true
	case <-time.After(bound):
		var zero T
		return zero, false
	}
}

// callWithin runs call in its own goroutine, returns its result and fails the test when it has
// not returned within lifecycleWatchdog.
func callWithin[T any](t *testing.T, label string, call func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- call() }()
	v, ok := receiveWithin(done, lifecycleWatchdog)
	require(t, ok, "%s did not return within %s", label, lifecycleWatchdog)
	return v
}

var errImageNoResult = errors.New("request did not return within its bound")

// launch starts the request in its own goroutine and delivers its result.
func launch(round *ImageRound, ctx context.Context, sourceID string, start byte, byteLimit uint32) <-chan imageResult {
	done := make(chan imageResult, 1)
	go func() {
		q, err := round.Request(ctx, sourceID, imageStart(start), byteLimit)
		done <- imageResult{q, err}
	}()
	return done
}

// requestWithin returns the request's result, or errImageNoResult when it has not returned
// within bound.
func requestWithin(bound time.Duration, round *ImageRound, ctx context.Context, sourceID string, start byte, byteLimit uint32) imageResult {
	result, ok := receiveWithin(launch(round, ctx, sourceID, start, byteLimit), bound)
	if !ok {
		result.err = errImageNoResult
	}
	return result
}

func (f *imageTestFixture) request(round *ImageRound, ctx context.Context, session int, start byte) imageResult {
	return requestWithin(lifecycleWatchdog, round, ctx, f.ids[session], start, imageTestByteLimit)
}

func (f *imageTestFixture) goRequest(round *ImageRound, ctx context.Context, session int, start byte) <-chan imageResult {
	return launch(round, ctx, f.ids[session], start, imageTestByteLimit)
}

func awaitImageResult(t *testing.T, done <-chan imageResult, label string) imageResult {
	t.Helper()
	result, ok := receiveWithin(done, lifecycleWatchdog)
	require(t, ok, "%s: Request did not return within %s", label, lifecycleWatchdog)
	return result
}

// requireQueryResult checks that got carries the query want and that its error is wantErr itself,
// not a value that wraps or matches it.
func requireQueryResult(t *testing.T, got imageResult, want consensus.UTXOImageQuery, wantErr error, label string) {
	t.Helper()
	ok := got.q == want && got.err == wantErr //nolint:errorlint // The returned error is wantErr itself, not a value that wraps it.
	require(t, ok, "%s: q=%+v err=%v, want q=%+v err=%v", label, got.q, got.err, want, wantErr)
}

// requireImageResult checks the query with wantID and start at the test anchor and byte limit and
// that the error is wantErr itself.
func requireImageResult(t *testing.T, got imageResult, wantID uint64, start byte, wantErr error, label string) {
	t.Helper()
	requireQueryResult(t, got, expectedImageQuery(wantID, start), wantErr, label)
}

func (f *imageTestFixture) admitted(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte, wantID uint64) {
	t.Helper()
	requireImageResult(t, f.request(round, ctx, session, start), wantID, start, nil, fmt.Sprintf("request session %d start %d", session, start))
}

// failedOnClosed requests start, new to round, on session after its connection was closed, with
// no instance of the Service ended, and checks the failed write: the admitted query with wantID
// and net.ErrClosed, no frame, one more Close, net.ErrClosed as the last error, and one distinct
// start, source attempt and admitted request charged with no current assignment or request byte
// left held.
func (f *imageTestFixture) failedOnClosed(t *testing.T, round *ImageRound, session int, start byte, wantID uint64) {
	t.Helper()
	before := f.snapshot(round, session)
	got := f.request(round, context.Background(), session, start)
	after := f.snapshot(round, session)
	requireImageResult(t, got, wantID, start, net.ErrClosed, "request on the closed connection")
	charge := imageUsage(0, 1, 1, 1, 0)
	before.perPeer.add(charge)
	before.global.add(charge)
	require(t, after.perPeer == before.perPeer && after.global == before.global && after.wire == before.wire, "request on the closed connection: usage %v %v, want %v %v, wire bytes %d->%d", after.perPeer, after.global, before.perPeer, before.global, before.wire, after.wire)
	require(t, after.closes == before.closes+1 && after.lastError == net.ErrClosed.Error(), "request on the closed connection: closes %d->%d, last error %q", before.closes, after.closes, after.lastError)
}

// imageSnapshot is the owner state a refused Request is compared on.
type imageSnapshot struct {
	lastID    uint64
	perPeer   imageUnitVector
	global    imageUnitVector
	current   int
	attempted int
	wire      int
	closes    int
	lastError string
	banScore  int
}

// lockRequester takes the requester mutex, failing the test when it is not free within
// lifecycleWatchdog.
func (f *imageTestFixture) lockRequester() *imageRequester {
	f.t.Helper()
	req := f.s.imageRequester
	waitUntil(f.t, req.mu.TryLock, "requester mutex")
	return req
}

// peerFault returns session's last error and ban score, failing the test when its state mutex is
// not free within lifecycleWatchdog.
func (f *imageTestFixture) peerFault(session int) (string, int) {
	f.t.Helper()
	p := f.peers[session]
	waitUntil(f.t, p.stateMu.TryLock, "peer state mutex")
	defer p.stateMu.Unlock()
	return p.state.LastError, p.state.BanScore
}

func (f *imageTestFixture) snapshot(round *ImageRound, session int) imageSnapshot {
	req := f.lockRequester()
	snap := imageSnapshot{lastID: req.lastID[f.peers[session]], perPeer: *round.usageFor(f.peers[session]), global: round.global, current: len(req.current), attempted: len(round.attempted)}
	req.mu.Unlock()
	_, snap.closes = f.conns[session].snapshot()
	snap.wire = len(f.wires[session].bytes())
	snap.lastError, snap.banScore = f.peerFault(session)
	return snap
}

// imageDrop is the number of current assignments the pass of a refused request releases: of
// the refusing round on its session, of the refusing round in total and of the Service.
type imageDrop struct {
	perPeer, global uint64
	current         int
}

func (f *imageTestFixture) refusedWith(t *testing.T, round *ImageRound, ctx context.Context, sourceID string, session int, start byte, byteLimit uint32, want error) {
	t.Helper()
	f.refusedDropping(t, round, ctx, sourceID, session, start, byteLimit, want, imageDrop{})
}

// refusedAfterPass requests start on session and checks the refusal want, whose pass releases
// exactly drop and changes nothing else.
func (f *imageTestFixture) refusedAfterPass(t *testing.T, round *ImageRound, session int, start byte, want error, drop imageDrop) {
	t.Helper()
	f.refusedDropping(t, round, context.Background(), f.ids[session], session, start, imageTestByteLimit, want, drop)
}

func (f *imageTestFixture) refusedDropping(t *testing.T, round *ImageRound, ctx context.Context, sourceID string, session int, start byte, byteLimit uint32, want error, drop imageDrop) {
	t.Helper()
	before := f.snapshot(round, session)
	got := requestWithin(lifecycleWatchdog, round, ctx, sourceID, start, byteLimit)
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, want, fmt.Sprintf("start %d", start))
	after := f.snapshot(round, session)
	wantPerPeer := imageMinus(before.perPeer, imageUsage(drop.perPeer, 0, 0, 0, 0))
	wantGlobal := imageMinus(before.global, imageUsage(drop.global, 0, 0, 0, 0))
	require(t, after.lastID == before.lastID && after.perPeer == wantPerPeer && after.global == wantGlobal, "start %d: refusal changed id %d->%d or usage %v %v, want %v %v", start, before.lastID, after.lastID, after.perPeer, after.global, wantPerPeer, wantGlobal)
	require(t, after.current == before.current-drop.current && after.attempted == before.attempted && after.wire == before.wire, "start %d: refusal left %d current from %d, want %d, marked %d->%d or wrote %d->%d", start, after.current, before.current, before.current-drop.current, before.attempted, after.attempted, before.wire, after.wire)
	require(t, after.closes == before.closes && after.lastError == before.lastError && after.banScore == before.banScore, "start %d: refusal closed %d->%d or faulted %q/%d", start, before.closes, after.closes, after.lastError, after.banScore)
}

func (f *imageTestFixture) refused(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte, want error) {
	t.Helper()
	f.refusedWith(t, round, ctx, f.ids[session], session, start, imageTestByteLimit, want)
}

func (f *imageTestFixture) lastID(session int) uint64 {
	req := f.lockRequester()
	defer req.mu.Unlock()
	return req.lastID[f.peers[session]]
}

func (f *imageTestFixture) setLastID(session int, id uint64) {
	req := f.lockRequester()
	req.lastID[f.peers[session]] = id
	req.mu.Unlock()
}

func (f *imageTestFixture) usage(round *ImageRound, session int) (imageUnitVector, imageUnitVector) {
	req := f.lockRequester()
	defer req.mu.Unlock()
	return *round.usageFor(f.peers[session]), round.global
}

// imageUsage is the usage vector of the ImageUnits value with the given CurrentAssignments,
// DistinctStarts, SourceAttempts, AdmittedRequests and PendingNetworkBytes and zero in the other
// fields.
func imageUsage(current, starts, attempts, admitted, pending uint64) imageUnitVector {
	return ImageUnits{CurrentAssignments: current, DistinctStarts: starts, SourceAttempts: attempts, AdmittedRequests: admitted, PendingNetworkBytes: pending}.vector()
}

// imageMinus returns v less u, unit by unit.
func imageMinus(v, u imageUnitVector) imageUnitVector {
	for i := range v {
		v[i] -= u[i]
	}
	return v
}

// requireUsage compares round's whole usage vector on session with perPeer and its whole
// global usage vector with global.
func (f *imageTestFixture) requireUsage(t *testing.T, round *ImageRound, session int, perPeer, global imageUnitVector, label string) {
	t.Helper()
	gotPerPeer, gotGlobal := f.usage(round, session)
	require(t, gotPerPeer == perPeer && gotGlobal == global, "%s: usage per peer %v global %v, want %v %v", label, gotPerPeer, gotGlobal, perPeer, global)
}

// instance returns the current instance of start at the test anchor, or nil.
func (f *imageTestFixture) instance(start byte) *imageInstance {
	req := f.lockRequester()
	defer req.mu.Unlock()
	return req.current[imageKey{imageTestAnchor, imageStart(start)}]
}

func (f *imageTestFixture) ended(inst *imageInstance) (bool, error) {
	req := f.lockRequester()
	defer req.mu.Unlock()
	return inst.retired, inst.end
}

func (f *imageTestFixture) waitRetired(t *testing.T, inst *imageInstance, label string) error {
	t.Helper()
	waitUntil(t, func() bool { retired, _ := f.ended(inst); return retired }, label+": retirement")
	_, end := f.ended(inst)
	return end
}

func (f *imageTestFixture) waitAdmitted(t *testing.T, session int, id uint64, label string) {
	t.Helper()
	waitUntil(t, func() bool { return f.lastID(session) == id }, fmt.Sprintf("%s: allocation of id %d", label, id))
}

// imageRequestCommand is the 12-byte command field 6765747574786f696d670000 of the request frame
// (RUBIN_L1_P2P_AUX.md Section 7.1).
var imageRequestCommand = [12]byte{0x67, 0x65, 0x74, 0x75, 0x74, 0x78, 0x6f, 0x69, 0x6d, 0x67, 0x00, 0x00}

// frames returns the decoded queries of the frames written on session whose command field,
// NUL-padded to 12 bytes as readFrame checked it, is imageRequestCommand, in order.
func (f *imageTestFixture) frames(t *testing.T, session int) []consensus.UTXOImageQuery {
	t.Helper()
	cfg := f.s.cfg.PeerRuntimeConfig
	reader := bytes.NewReader(f.wires[session].bytes())
	var queries []consensus.UTXOImageQuery
	for reader.Len() > 0 {
		frame, err := readFrame(reader, networkMagic(cfg.Network), cfg.MaxMessageSize)
		must(t, err, "readFrame")
		if !isImageRequestCommand(frame.Command) {
			continue
		}
		q, ok := consensus.DecodeUTXOImageRequest(frame.Payload)
		require(t, ok, "getutxoimg payload does not decode")
		queries = append(queries, q)
	}
	return queries
}

// isImageRequestCommand reports whether command, NUL-padded to 12 bytes as readFrame checked it,
// is imageRequestCommand.
func isImageRequestCommand(command string) bool {
	if len(command) > len(imageRequestCommand) {
		return false
	}
	var field [12]byte
	copy(field[:], command)
	return field == imageRequestCommand
}

// requireFrames compares the decoded getutxoimg queries written on session with want, field by
// field and in order.
func (f *imageTestFixture) requireFrames(t *testing.T, session int, label string, want ...consensus.UTXOImageQuery) {
	t.Helper()
	got := f.frames(t, session)
	require(t, slices.Equal(got, want), "%s: session %d getutxoimg queries=%+v, want %+v", label, session, got, want)
}

func (f *imageTestFixture) closes(session int) int {
	_, closes := f.conns[session].snapshot()
	return closes
}

// holdWrite starts a ping frame write on session that stalls in its connection; the frame
// write keeps the session's writeMu until release lets it finish. release returns that write's
// error and fails the test when the write has not returned within lifecycleWatchdog.
func (f *imageTestFixture) holdWrite(t *testing.T, session int) (release func() error) {
	t.Helper()
	stall := f.wires[session].armStall()
	done := make(chan error, 1)
	go func() { done <- f.peers[session].send(messagePing, make([]byte, 8)) }()
	requireChannelClosed(t, stall.entered, "holder write")
	return func() error {
		t.Helper()
		stall.release <- nil
		err, ok := receiveWithin(done, lifecycleWatchdog)
		require(t, ok, "holder write did not return within %s", lifecycleWatchdog)
		return err
	}
}

func requireNoImageResult(t *testing.T, done <-chan imageResult, window time.Duration, label string) {
	t.Helper()
	result, returned := receiveWithin(done, window)
	require(t, !returned, "%s: Request returned q=%+v err=%v while it had to wait", label, result.q, result.err)
}

// requireNoClockRead checks that the controlled clock is not read within lifecycleSettle.
func (f *imageTestFixture) requireNoClockRead(t *testing.T, label string) {
	t.Helper()
	reads := f.clock.readCount()
	time.Sleep(lifecycleSettle)
	requireEqual(t, f.clock.readCount(), reads, label)
}

func TestImageRequesterRound(t *testing.T) {
	t.Run("ids start at one and increase across rounds, expiry, cancellation and a failed write", testImageIDsIncrease)
	t.Run("the maximum id is issued once and later requests on that session refuse without wrap", testImageIDMaximum)
	t.Run("one current assignment per anchor and start across the service", testImageOneCurrent)
	t.Run("count limits pass at equality and refuse one over before an id", testImageCountLimits)
	t.Run("pending request bytes pass at equality and refuse one over", testImagePendingBytes)
	t.Run("distinct starts count the round's admitted starts", testImageDistinctStarts)
	t.Run("usage and release are per round", testImagePerRoundUsage)
	t.Run("attempt and round deadlines and no renewal", testImageDeadlines)
	t.Run("pre-write decision at D and one tick after", testImagePreWriteAtDeadline)
	t.Run("an end while waiting for writeMu stops the write", testImageEndBeforeWrite)
	t.Run("a request past the checks that need no registry state retires the ended instances of the service before its round deadline check", testImageRequestRetiresEnded)
	t.Run("an end during the running write", testImageEndDuringWrite)
	t.Run("the frame write deadline is the frame budget, not D, RD or a ctx deadline", testImageFrameWriteDeadline)
	t.Run("ctx callbacks and the deadline timer with no further request", testImageCallbacksAndTimer)
	t.Run("a failed write keeps the query, the id and the work and retires only that assignment", testImageFailedWrite)
	t.Run("a stale handle leaves its replacement current", testImageStaleHandle)
	t.Run("round refusals in order", testImageRoundRefusals)
	t.Run("round construction at the domain bounds and with a done ctx", testImageRoundAdmits)
	t.Run("request refusals in order", testImageRequestRefusals)
	t.Run("deadline representability", testImageRepresentability)
	t.Run("a request reaches only the connection captured for its source id", testImageCapturedSourceID)
	t.Run("service close", testImageServiceClose)
	t.Run("an unwind after admission", testImageUnwind)
}

func testImageIDsIncrease(t *testing.T) {
	f := newImageTestFixture(t, 2)
	first := f.round(t, imageTestLimits(), 0, 1)
	f.admitted(t, first, context.Background(), 0, 1, 1)
	f.clock.add(10*time.Second + time.Nanosecond)
	second := f.round(t, imageTestLimits(), 0, 1)
	f.admitted(t, second, context.Background(), 0, 1, 2)
	ctx, cancel := context.WithCancel(context.Background())
	f.admitted(t, second, ctx, 0, 2, 3)
	inst := f.instance(2)
	cancel()
	f.waitRetired(t, inst, "canceled instance")
	f.admitted(t, second, context.Background(), 1, 2, 1)
	f.admitted(t, second, context.Background(), 0, 3, 4)
	writeErr := errors.New("scripted write failure")
	f.wires[0].armStall().release <- writeErr
	requireImageResult(t, f.request(second, context.Background(), 0, 4), 5, 4, writeErr, "failed write")
	f.requireUsage(t, second, 0, imageUsage(2, 4, 4, 4, 0), imageUsage(3, 4, 5, 5, 0), "after the failed write")
	f.failedOnClosed(t, second, 0, 5, 6)
	f.requireFrames(t, 0, "ids across rounds", expectedImageQuery(1, 1), expectedImageQuery(2, 1), expectedImageQuery(3, 2), expectedImageQuery(4, 3))
	renewed := f.addSession(t, f.ids[0], "192.0.2.80:9")
	f.admitted(t, f.round(t, imageTestLimits(), renewed), context.Background(), renewed, 6, 1)
}

func testImageIDMaximum(t *testing.T) {
	f := newImageTestFixture(t, 2)
	f.setLastID(0, 18446744073709551614)
	round := f.round(t, imageTestLimits(), 0, 1)
	f.admitted(t, round, context.Background(), 0, 1, 18446744073709551615)
	f.requireFrames(t, 0, "maximum id", expectedImageQuery(18446744073709551615, 1))
	f.refused(t, round, context.Background(), 0, 2, errImageIDExhausted)
	requireEqual(t, f.lastID(0), uint64(18446744073709551615), "last id after refusal")
	f.requireFrames(t, 0, "after refusal", expectedImageQuery(18446744073709551615, 1))
	f.admitted(t, round, context.Background(), 1, 2, 1)
}

func testImageOneCurrent(t *testing.T) {
	f := newImageTestFixture(t, 3)
	first := f.round(t, imageTestLimits(), 0, 1, 2)
	second := f.round(t, imageTestLimits(), 0, 1, 2)
	stall := f.wires[0].armStall()
	pending := f.goRequest(first, context.Background(), 0, 1)
	requireChannelClosed(t, stall.entered, "first request write")
	f.refused(t, second, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.admitted(t, second, context.Background(), 1, 2, 1)
	stall.release <- nil
	requireImageResult(t, awaitImageResult(t, pending, "stalled request"), 1, 1, nil, "stalled request")
	f.requireFrames(t, 1, "parallel start", expectedImageQuery(1, 2))
	other := imageTestAnchor
	other.Height = 8
	otherRound, err := f.begin(context.Background(), ImageRoundConfig{Anchor: other, SourceIDs: []string{f.ids[2]}, Limits: imageTestLimits()})
	must(t, err, "BeginImageRound other anchor")
	wantOther := expectedImageQuery(1, 1)
	wantOther.Height = 8
	requireQueryResult(t, f.request(otherRound, context.Background(), 2, 1), wantOther, nil, "other anchor same start")
	f.requireFrames(t, 2, "other anchor same start", wantOther)
	f.clock.add(10*time.Second + time.Nanosecond)
	f.refusedAfterPass(t, first, 0, 1, errImageAttempted, imageDrop{1, 1, 3})
	f.admitted(t, first, context.Background(), 1, 1, 2)
}

func testImageCountLimits(t *testing.T) {
	units := []struct {
		name     string
		field    func(*ImageUnits) *uint64
		released bool
	}{
		{"current assignments", func(u *ImageUnits) *uint64 { return &u.CurrentAssignments }, true},
		{"distinct starts", func(u *ImageUnits) *uint64 { return &u.DistinctStarts }, false},
		{"source attempts", func(u *ImageUnits) *uint64 { return &u.SourceAttempts }, false},
		{"admitted requests", func(u *ImageUnits) *uint64 { return &u.AdmittedRequests }, false},
	}
	for _, tc := range units {
		for _, global := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s global=%v", tc.name, global), func(t *testing.T) {
				f := newImageTestFixture(t, 2)
				limits := imageTestLimits()
				scope := &limits.PerPeer
				if global {
					scope = &limits.Global
				}
				*tc.field(scope) = 2
				round := f.round(t, limits, 0, 1)
				ctx, cancel := context.WithCancel(context.Background())
				f.admitted(t, round, ctx, 0, 1, 1)
				inst := f.instance(1)
				f.admitted(t, round, context.Background(), 0, 2, 2)
				f.refused(t, round, context.Background(), 0, 3, errImageLimit)
				if global {
					f.refused(t, round, context.Background(), 1, 3, errImageLimit)
				} else {
					f.admitted(t, round, context.Background(), 1, 3, 1)
				}
				cancel()
				f.waitRetired(t, inst, "canceled instance")
				if tc.released {
					f.admitted(t, round, context.Background(), 0, 4, 3)
					return
				}
				f.refused(t, round, context.Background(), 0, 4, errImageLimit)
				f.requireFrames(t, 0, "frames", expectedImageQuery(1, 1), expectedImageQuery(2, 2))
			})
		}
	}
}

func testImagePendingBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		global bool
	}{{"per-peer limit", false}, {"global limit", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			limits := imageTestLimits()
			limits.PerPeer.PendingNetworkBytes = 120
			if tc.global {
				limits.Global, limits.PerPeer = limits.PerPeer, limits.Global
			}
			round := f.round(t, limits, 0)
			f.admitted(t, round, context.Background(), 0, 1, 1)
			f.admitted(t, round, context.Background(), 0, 2, 2)
			f.requireUsage(t, round, 0, imageUsage(2, 2, 2, 2, 0), imageUsage(2, 2, 2, 2, 0), "after two writes")
			tight := imageTestLimits()
			if tc.global {
				tight.Global.PendingNetworkBytes = 119
			} else {
				tight.PerPeer.PendingNetworkBytes = 119
			}
			f.refused(t, f.round(t, tight, 0), context.Background(), 0, 3, errImageLimit)
		})
	}
}

func testImageDistinctStarts(t *testing.T) {
	f := newImageTestFixture(t, 2)
	limits := imageTestLimits()
	limits.Global.DistinctStarts = 1
	round := f.round(t, limits, 0, 1)
	f.admitted(t, round, context.Background(), 0, 1, 1)
	f.clock.add(10*time.Second + time.Nanosecond)
	f.admitted(t, round, context.Background(), 1, 1, 1)
	f.requireUsage(t, round, 1, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "the start admitted again on the second session")
	f.clock.add(10*time.Second + time.Nanosecond)
	f.refusedAfterPass(t, round, 0, 2, errImageLimit, imageDrop{0, 1, 1})
	f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 2, 2, 0), "after the refusal")
}

func testImagePerRoundUsage(t *testing.T) {
	t.Run("another round's usage does not count", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		limits := imageTestLimits()
		for _, scope := range []*ImageUnits{&limits.PerPeer, &limits.Global} {
			scope.CurrentAssignments, scope.DistinctStarts, scope.SourceAttempts, scope.AdmittedRequests, scope.PendingNetworkBytes = 1, 1, 1, 1, 120
		}
		r1, r2 := f.round(t, limits, 0), f.round(t, limits, 0)
		stall := f.wires[0].armStall()
		first := f.goRequest(r1, context.Background(), 0, 1)
		requireChannelClosed(t, stall.entered, "first round write")
		second := f.goRequest(r2, context.Background(), 0, 2)
		f.waitAdmitted(t, 0, 2, "second round admission")
		f.refused(t, r1, context.Background(), 0, 2, errImageAssignmentCurrent)
		stall.release <- nil
		requireImageResult(t, awaitImageResult(t, first, "first round"), 1, 1, nil, "first round")
		requireImageResult(t, awaitImageResult(t, second, "second round"), 2, 2, nil, "second round")
		f.requireFrames(t, 0, "both rounds", expectedImageQuery(1, 1), expectedImageQuery(2, 2))
	})
	t.Run("a retirement releases its own round", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		limits := imageTestLimits()
		limits.PerPeer.CurrentAssignments, limits.Global.CurrentAssignments = 1, 1
		r1, r2 := f.round(t, limits, 0), f.round(t, limits, 0)
		t0 := f.clock.Now()
		f.admitted(t, r1, context.Background(), 0, 1, 1)
		f.clock.add(time.Second)
		f.admitted(t, r2, context.Background(), 0, 2, 2)
		f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
		f.refusedAfterPass(t, r2, 0, 3, errImageLimit, imageDrop{0, 0, 1})
		f.admitted(t, r1, context.Background(), 0, 4, 3)
	})
	t.Run("a value copy of a round is that round", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		limits := imageTestLimits()
		limits.Global.AdmittedRequests = 1
		round := f.round(t, limits, 0, 1)
		copied := *round
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.refused(t, &copied, context.Background(), 1, 2, errImageLimit)
	})
}

func testImageDeadlines(t *testing.T) {
	f := newImageTestFixture(t, 5)
	t0 := f.clock.Now()
	limits := imageTestLimits()
	limits.RoundLifetime = 60 * time.Second
	round := f.round(t, limits, 0, 1, 2, 3, 4)
	f.admitted(t, round, context.Background(), 0, 1, 1)
	first := f.instance(1)
	require(t, first.deadline.Equal(t0.Add(10*time.Second)), "D=%v", first.deadline)
	f.clock.set(t0.Add(10 * time.Second))
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
	f.admitted(t, round, context.Background(), 1, 1, 1)
	require(t, f.instance(1).deadline.Equal(t0.Add(20*time.Second+time.Nanosecond)) && first.deadline.Equal(t0.Add(10*time.Second)), "reassigned D=%v first D=%v", f.instance(1).deadline, first.deadline)
	writeErr := errors.New("scripted write failure")
	f.wires[4].armStall().release <- writeErr
	requireImageResult(t, f.request(round, context.Background(), 4, 5), 1, 5, writeErr, "failed write")
	f.requireUsage(t, round, 4, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 2, 3, 3, 0), "after the failed write")
	ctx, cancel := context.WithCancel(context.Background())
	f.admitted(t, round, ctx, 3, 6, 1)
	ended := f.instance(6)
	cancel()
	f.waitRetired(t, ended, "canceled instance")
	f.clock.set(t0.Add(55 * time.Second))
	f.admitted(t, round, context.Background(), 2, 2, 1)
	require(t, f.instance(2).deadline.Equal(t0.Add(60*time.Second)), "D capped by RD: %v", f.instance(2).deadline)
	f.clock.set(t0.Add(60*time.Second - time.Nanosecond))
	f.admitTimerSpent(t, round, 2, 3, 2)
	f.clock.set(t0.Add(60 * time.Second))
	f.refused(t, round, context.Background(), 0, 4, errImageRoundDeadline)
	require(t, round.roundDeadline.Equal(t0.Add(60*time.Second)) && round.limits == limits, "RD=%v limits=%+v, want %+v", round.roundDeadline, round.limits, limits)
	f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(2, 5, 6, 6, 0), "consumed usage")
	f.clock.set(t0.Add(60*time.Second + time.Nanosecond))
	f.refusedAfterPass(t, round, 0, 4, errImageRoundDeadline, imageDrop{0, 2, 2})
}

func testImagePreWriteAtDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		past bool
	}{{"now at D writes the frame", false}, {"now one tick past D writes no frame", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			t0 := f.clock.Now()
			round := f.round(t, imageTestLimits(), 0)
			release := f.holdWrite(t, 0)
			pending := f.goRequest(round, context.Background(), 0, 1)
			f.waitAdmitted(t, 0, 1, "parked request")
			at := t0.Add(10 * time.Second)
			if tc.past {
				at = at.Add(time.Nanosecond)
			}
			f.clock.set(at)
			if tc.past {
				requireImageResult(t, awaitImageResult(t, pending, "one tick past D"), 1, 1, errImageExpired, "one tick past D")
			}
			must(t, release(), "holder write")
			if tc.past {
				f.requireFrames(t, 0, "one tick past D")
				f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "one tick past D")
				return
			}
			requireImageResult(t, awaitImageResult(t, pending, "at D"), 1, 1, nil, "at D")
			f.requireFrames(t, 0, "at D", expectedImageQuery(1, 1))
			f.requireUsage(t, round, 0, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 1, 1, 0), "at D")
		})
	}
	t.Run("with writeMu free, an end first seen by a clock read made with writeMu held stops the write", testImageEndSeenUnderWriteMu)
	t.Run("an end recorded by another session's pass is kept when a ctx of the parked request ends before its pre-write decision", testImageRecordedEndKept)
}

// imageEndCase ends a request parked on writeMu. With callback set, the end cancels a ctx inside
// the parked request's own clock read, so that request retires the instance and the launched
// ctx callback reads the clock after it; the attempt lifetime is then 50 ms, and the end is
// applied only after the deadline timer has read the clock, short of D.
type imageEndCase struct {
	name     string
	lifetime time.Duration
	apply    func(f *imageTestFixture, t0 time.Time, cancelRequest, cancelRound func())
	want     error
	notWant  []error
	newRound bool
	callback bool
}

func imageEndCases() []imageEndCase {
	return []imageEndCase{
		{name: "request ctx canceled", lifetime: 50 * time.Millisecond, apply: func(f *imageTestFixture, _ time.Time, cancelRequest, _ func()) { f.clock.cancelOnRead(cancelRequest) }, want: context.Canceled, callback: true},
		{
			name: "now after D", apply: func(f *imageTestFixture, t0 time.Time, _, _ func()) {
				f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
			},
			want: errImageExpired, notWant: []error{errImageRoundDeadline, context.DeadlineExceeded, os.ErrDeadlineExceeded},
		},
		{
			name: "now at RD with D equal to RD", lifetime: time.Hour, apply: func(f *imageTestFixture, t0 time.Time, _, _ func()) { f.clock.set(t0.Add(time.Hour)) },
			want: errImageRoundDeadline, notWant: []error{errImageExpired}, newRound: true,
		},
		{name: "round ctx canceled", lifetime: 50 * time.Millisecond, apply: func(f *imageTestFixture, _ time.Time, _, cancelRound func()) { f.clock.cancelOnRead(cancelRound) }, want: context.Canceled, newRound: true, callback: true},
		{
			name: "now at RD with D before RD", apply: func(f *imageTestFixture, t0 time.Time, _, _ func()) { f.clock.set(t0.Add(time.Hour)) },
			want: errImageExpired, notWant: []error{errImageRoundDeadline}, newRound: true,
		},
		{name: "request ctx canceled at the read that moves now after D", lifetime: 50 * time.Millisecond, apply: func(f *imageTestFixture, t0 time.Time, cancelRequest, _ func()) {
			f.clock.jumpOnRead(t0.Add(50*time.Millisecond+time.Nanosecond), cancelRequest)
		}, want: context.Canceled, callback: true},
	}
}

func testImageEndBeforeWrite(t *testing.T) {
	for _, tc := range imageEndCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0 := f.clock.Now()
			limits := imageTestLimits()
			if tc.lifetime != 0 {
				limits.AttemptLifetime = tc.lifetime
			}
			roundCtx, cancelRound := context.WithCancel(context.Background())
			defer cancelRound()
			round := f.roundCtx(t, roundCtx, limits, 0, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			release := f.holdWrite(t, 0)
			var timerRead <-chan struct{}
			if tc.callback {
				timerRead = f.clock.applyImageEndRead()
			}
			pending := f.goRequest(round, ctx, 0, 1)
			f.waitAdmitted(t, 0, 1, "parked request")
			if tc.callback {
				requireChannelClosed(t, timerRead, "deadline timer read")
			}
			tc.apply(f, t0, cancel, cancelRound)
			got := awaitImageResult(t, pending, "parked request")
			requireImageResult(t, got, 1, 1, tc.want, "while another write holds writeMu")
			for _, other := range tc.notWant {
				require(t, !errors.Is(got.err, other), "end error %v matches %v", got.err, other)
			}
			requireEqual(t, f.closes(0), 0, "session closes after the end")
			if tc.callback {
				f.awaitReadsAfterHook(t, 1, "ctx callback")
			}
			must(t, release(), "holder write")
			f.requireFrames(t, 0, "after the end")
			f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "after the end")
			follow := round
			if tc.newRound {
				follow = f.round(t, imageTestLimits(), 0, 1)
			}
			f.admitted(t, follow, context.Background(), 0, 2, 2)
			f.admitted(t, follow, context.Background(), 1, 1, 1)
			requireEqual(t, f.closes(0), 0, "session closes after the follow-up requests")
		})
	}
	t.Run("frozen now keeps the wait parked until the ctx ends", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		limits := imageTestLimits()
		limits.AttemptLifetime = 50 * time.Millisecond
		round := f.round(t, limits, 0)
		ctx, cancel := context.WithCancel(context.Background())
		release := f.holdWrite(t, 0)
		// Neither ctx is done before the canceling hook, so of the ctx callbacks and the deadline
		// timer only the timer reads the clock; the hook is installed after that read.
		timerRead := f.clock.applyImageEndRead()
		pending := f.goRequest(round, ctx, 0, 1)
		f.waitAdmitted(t, 0, 1, "parked request")
		requireNoImageResult(t, pending, 200*time.Millisecond, "frozen now")
		requireChannelClosed(t, timerRead, "deadline timer read")
		f.clock.cancelOnRead(cancel)
		got := awaitImageResult(t, pending, "canceled wait")
		requireImageResult(t, got, 1, 1, context.Canceled, "canceled wait")
		f.awaitReadsAfterHook(t, 1, "ctx callback")
		must(t, release(), "holder write")
		f.requireFrames(t, 0, "frozen now")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "canceled wait")
	})
}

func testImageEndSeenUnderWriteMu(t *testing.T) {
	f := newImageTestFixture(t, 1)
	t0 := f.clock.Now()
	round := f.round(t, imageTestLimits(), 0)
	session := f.peers[0]
	// A read made while writeMu is free leaves the clock and waits for the next read; the
	// first read made while writeMu is held moves now past D.
	var endUnderWriteMu func(time.Time) time.Time
	endUnderWriteMu = func(now time.Time) time.Time {
		if session.writeMu.TryLock() {
			session.writeMu.Unlock()
			f.clock.onRead = endUnderWriteMu
			return now
		}
		return t0.Add(10*time.Second + time.Nanosecond)
	}
	f.clock.onNextRead(endUnderWriteMu)
	requireImageResult(t, f.request(round, context.Background(), 0, 1), 1, 1, errImageExpired, "end seen under writeMu")
	f.requireFrames(t, 0, "end seen under writeMu")
	f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "end seen under writeMu")
	next := awaitImageResult(t, f.goRequest(round, context.Background(), 0, 2), "next request on the session")
	requireImageResult(t, next, 2, 2, nil, "next request on the session")
	f.requireFrames(t, 0, "next request on the session", expectedImageQuery(2, 2))
}

// imageCalledFrom reports whether the calling goroutine's stack holds a function whose name ends
// with suffix.
func imageCalledFrom(suffix string) bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, suffix) {
			return true
		}
		if !more {
			return false
		}
	}
}

// testImageRecordedEndKept parks a request on writeMu. The admission clock read of a request on
// another session moves now past D, so its pass, under the requester mutex, retires the parked
// instance with errImageExpired. The first clock read of a pre-write decision after it then
// cancels a ctx of the parked request; the parked request returns the recorded end, releases its
// request bytes once and writes no frame.
func testImageRecordedEndKept(t *testing.T) {
	for _, tc := range []struct {
		name  string
		round bool
	}{{"request ctx", false}, {"round ctx", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0 := f.clock.Now()
			roundCtx, cancelRound := context.WithCancel(context.Background())
			defer cancelRound()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			end := cancel
			if tc.round {
				end = cancelRound
			}
			parked := f.roundCtx(t, roundCtx, imageTestLimits(), 0)
			other := f.round(t, imageTestLimits(), 1)
			release := f.holdWrite(t, 0)
			pending := f.goRequest(parked, ctx, 0, 1)
			f.waitAdmitted(t, 0, 1, "parked request")
			inst := f.instance(1)
			passed := false
			var hook func(time.Time) time.Time
			hook = func(now time.Time) time.Time {
				switch {
				case !passed && imageCalledFrom(".(*ImageRound).admit"):
					passed = true
					now = t0.Add(10*time.Second + time.Nanosecond)
				case passed && imageCalledFrom(".(*ImageRound).endBeforeWrite"):
					end()
					return now
				}
				f.clock.onRead = hook
				return now
			}
			f.clock.onNextRead(hook)
			f.admitted(t, other, context.Background(), 1, 2, 1)
			got := awaitImageResult(t, pending, "parked request")
			requireImageResult(t, got, 1, 1, errImageExpired, "parked request")
			requireEqual(t, f.closes(0), 0, "session closes after the recorded end")
			_, recorded := f.ended(inst)
			require(t, recorded == errImageExpired, "recorded end=%v", recorded) //nolint:errorlint // The recorded end is errImageExpired itself.
			f.requireUsage(t, parked, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "after the recorded end")
			must(t, release(), "holder write")
			f.requireFrames(t, 0, "after the recorded end")
		})
	}
}

func testImageDoneContexts(t *testing.T) {
	f := newImageTestFixture(t, 1)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelExpired()
	done := f.roundCtx(t, expired, imageTestLimits(), 0)
	f.refused(t, done, canceled, 0, 1, context.Canceled)
	f.refused(t, done, context.Background(), 0, 1, context.DeadlineExceeded)
	live := f.round(t, imageTestLimits(), 0)
	f.refused(t, live, canceled, 0, 1, context.Canceled)
	f.refused(t, live, expired, 0, 1, context.DeadlineExceeded)
	f.admitted(t, live, context.Background(), 0, 1, 1)
}

// testImageDoneAtAdmissionRead admits start 1 on session 0, then requests start 1 on session 1
// with live ctxs whose admission clock read ends one ctx and moves now past the first instance's
// D. The request refuses with that ctx's error, allocates no ID, writes no frame and, for the
// Request ctx, leaves the first instance unretired; the next request with live ctxs is admitted
// with ID 1 on session 1. The Request ctx is an imageEndCtx or a context.WithCancel ctx.
func testImageDoneAtAdmissionRead(t *testing.T) {
	requestEnd, roundEnd := errors.New("request ctx ended"), errors.New("round ctx ended")
	endCtx := func() (context.Context, context.CancelFunc) { return newImageEndCtx(requestEnd) }
	cancelCtx := func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }
	for _, tc := range []struct {
		name       string
		round      bool
		requestCtx func() (context.Context, context.CancelFunc)
		want       error
	}{
		{"request ctx", false, endCtx, requestEnd},
		{"request ctx from context.WithCancel", false, cancelCtx, context.Canceled},
		{"round ctx", true, endCtx, roundEnd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0 := f.clock.Now()
			roundCtx, cancelRound := newImageEndCtx(roundEnd)
			defer cancelRound()
			ctx, cancel := tc.requestCtx()
			defer cancel()
			end := cancel
			if tc.round {
				end = cancelRound
			}
			round := f.roundCtx(t, roundCtx, imageTestLimits(), 0, 1)
			f.admitted(t, round, context.Background(), 0, 1, 1)
			first := f.instance(1)
			hooked := false
			var hook func(time.Time) time.Time
			hook = func(now time.Time) time.Time {
				if imageCalledFrom(".(*ImageRound).admit") {
					hooked = true
					end()
					return t0.Add(10*time.Second + time.Nanosecond)
				}
				f.clock.onRead = hook
				return now
			}
			f.clock.onNextRead(hook)
			got := f.request(round, ctx, 1, 1)
			requireQueryResult(t, got, consensus.UTXOImageQuery{}, tc.want, "ctx done at the admission clock read")
			require(t, hooked, "the admission clock read did not run the hook")
			requireEqual(t, f.lastID(1), uint64(0), "session 1 last id")
			f.requireFrames(t, 1, "ctx done at the admission clock read")
			requireEqual(t, f.closes(1), 0, "session 1 closes")
			if tc.round {
				f.admitted(t, f.round(t, imageTestLimits(), 0, 1), context.Background(), 1, 1, 1)
				return
			}
			retired, recorded := f.ended(first)
			require(t, !retired && recorded == nil, "first instance after the refusal: retired=%v end=%v, want current", retired, recorded)
			f.requireUsage(t, round, 0, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 1, 1, 0), "first instance's round after the refusal")
			f.admitted(t, round, context.Background(), 1, 1, 1)
			_, recorded = f.ended(first)
			require(t, recorded == errImageExpired, "first instance end after the next request=%v, want %v", recorded, errImageExpired) //nolint:errorlint // The recorded end is errImageExpired itself.
		})
	}
}

func testImageRequestRetiresEnded(t *testing.T) {
	t.Run("same round", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		t0 := f.clock.Now()
		round := f.round(t, imageTestLimits(), 0, 1)
		ctx, cancel := context.WithCancel(context.Background())
		f.admitted(t, round, ctx, 0, 1, 1)
		inst := f.instance(1)
		f.clock.set(t0.Add(10 * time.Second))
		f.refused(t, round, context.Background(), 0, 1, errImageAssignmentCurrent)
		f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
		f.refusedAfterPass(t, round, 0, 1, errImageAttempted, imageDrop{1, 1, 1})
		retired, end := f.ended(inst)
		require(t, retired && end == errImageExpired, "pass: retired=%v end=%v", retired, end) //nolint:errorlint // The recorded end is errImageExpired itself.
		f.admitted(t, round, context.Background(), 0, 2, 2)
		f.admitted(t, round, context.Background(), 1, 1, 1)
		cancel()
		time.Sleep(lifecycleSettle)
		_, end = f.ended(inst)
		require(t, end == errImageExpired, "end after cancellation=%v", end) //nolint:errorlint // The recorded end is errImageExpired itself.
		f.refused(t, round, context.Background(), 0, 1, errImageAssignmentCurrent)
		replacement := f.instance(1)
		require(t, replacement != nil && replacement.session == f.peers[1], "replacement not current")
		f.admitted(t, round, context.Background(), 0, 3, 3)
		requireEqual(t, f.lastID(1), uint64(1), "replacement session last id")
	})
	t.Run("another round's request retires the instance", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		t0 := f.clock.Now()
		r1, r2 := f.round(t, imageTestLimits(), 0), f.round(t, imageTestLimits(), 1)
		f.admitted(t, r1, context.Background(), 0, 1, 1)
		f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
		f.admitted(t, r2, context.Background(), 1, 1, 1)
		f.requireUsage(t, r1, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "first round after the pass")
	})
	t.Run("the pass records the request ctx end, then the round ctx end, then expiry", testImagePassEndOrder)
	t.Run("a request refused before the pass retires nothing", testImageEarlyRefusalRetiresNothing)
	t.Run("a request refused by the closed service retires nothing", testImageClosedRefusalRetiresNothing)
	t.Run("a refused request keeps the pass's retirement", testImageRefusalKeepsPass)
}

// imageEndCtx is a cancellable context whose Err, once it is done, is err, so a recorded end
// names the context it came from.
type imageEndCtx struct {
	context.Context
	err error
}

func (c imageEndCtx) Err() error {
	if c.Context.Err() == nil {
		return nil
	}
	return c.err
}

func newImageEndCtx(err error) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return imageEndCtx{ctx, err}, cancel
}

// testImagePassEndOrder ends an admitted instance at the next clock read. Unless the instance's
// deadline timer, due 10 s plus 1 ns after admission, reads first, that read is the admission
// read of another session's request, which holds the requester mutex across it, so that
// request's pass retires the instance ahead of its ctx callbacks and must have retired it for
// the request to take the same start.
func testImagePassEndOrder(t *testing.T) {
	requestEnd, roundEnd := errors.New("request ctx ended"), errors.New("round ctx ended")
	for _, tc := range []struct {
		name           string
		request, round bool
		after          time.Duration
		want           error
	}{
		{"request ctx done with now short of D", true, false, 0, requestEnd},
		{"round ctx done with now short of D", false, true, 0, roundEnd},
		{"request ctx done with now after D", true, false, 10*time.Second + time.Nanosecond, requestEnd},
		{"round ctx done with now after D", false, true, 10*time.Second + time.Nanosecond, roundEnd},
		{"request ctx and round ctx done with now after D", true, true, 10*time.Second + time.Nanosecond, requestEnd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0 := f.clock.Now()
			roundCtx, cancelRound := newImageEndCtx(roundEnd)
			defer cancelRound()
			ctx, cancel := newImageEndCtx(requestEnd)
			defer cancel()
			ended := f.roundCtx(t, roundCtx, imageTestLimits(), 0)
			f.admitted(t, ended, ctx, 0, 1, 1)
			inst := f.instance(1)
			before, _ := f.usage(ended, 0)
			caller := f.round(t, imageTestLimits(), 1)
			f.clock.jumpOnRead(t0.Add(tc.after), func() {
				if tc.request {
					cancel()
				}
				if tc.round {
					cancelRound()
				}
			})
			f.admitted(t, caller, context.Background(), 1, 1, 1)
			retired, end := f.ended(inst)
			require(t, retired && end == tc.want, "pass: retired=%v end=%v, want %v", retired, end, tc.want) //nolint:errorlint // The recorded end is the case's ctx error or errImageExpired itself.
			want := imageMinus(before, imageUsage(1, 0, 0, 0, 0))
			f.requireUsage(t, ended, 0, want, want, "pass usage of the single-source round")
			requireEqual(t, f.lastID(0), uint64(1), "session 0 last id")
		})
	}
}

// testImageEarlyRefusalRetiresNothing holds the requester mutex while the instance's ctx is
// canceled, so its ctx callback cannot retire it, and checks that requests refused by the listed checks
// that need no registry state return without that mutex and leave the instance unretired.
func testImageEarlyRefusalRetiresNothing(t *testing.T) {
	f := newImageTestFixture(t, 2)
	round := f.round(t, imageTestLimits(), 0)
	doneRoundCtx, cancelDoneRound := context.WithCancel(context.Background())
	cancelDoneRound()
	doneRound := f.roundCtx(t, doneRoundCtx, imageTestLimits(), 0)
	ctx, cancel := context.WithCancel(context.Background())
	f.admitted(t, round, ctx, 0, 1, 1)
	inst := f.instance(1)
	canceled, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	var nilCtx context.Context
	refusals := []struct {
		round     *ImageRound
		ctx       context.Context
		sourceID  string
		byteLimit uint32
		want      error
	}{
		{round, nilCtx, f.ids[0], imageTestByteLimit, errImageNilContext},
		{round, canceled, f.ids[0], imageTestByteLimit, context.Canceled},
		{doneRound, context.Background(), f.ids[0], imageTestByteLimit, context.Canceled},
		{round, context.Background(), f.ids[1], imageTestByteLimit, errImageUnknownSource},
		{round, context.Background(), f.ids[0], 150904, errImageRequestDomain},
	}
	req := f.lockRequester()
	cancel()
	results := make([]imageResult, len(refusals))
	for i, tc := range refusals {
		results[i] = requestWithin(lifecycleWatchdog, tc.round, tc.ctx, tc.sourceID, 2, tc.byteLimit)
	}
	retired := inst.retired
	req.mu.Unlock()
	for i, tc := range refusals {
		requireQueryResult(t, results[i], consensus.UTXOImageQuery{}, tc.want, fmt.Sprintf("refusal %d", i))
	}
	require(t, !retired, "a request refused before the pass retired the canceled instance")
	end := f.waitRetired(t, inst, "ctx callback")
	require(t, end == context.Canceled, "ctx callback end=%v", end) //nolint:errorlint // The recorded end is the ctx's Err() itself.
}

// testImageClosedRefusalRetiresNothing closes the Service with an instance current, then cancels
// its Request ctx and lets its deadline timer fire with now past D; the ctx callback and the timer
// are refused a lease. A request refused by the closed Service then leaves that ended instance
// unretired, its round's usage unchanged and the clock unread.
func testImageClosedRefusalRetiresNothing(t *testing.T) {
	runImageBubble(t, false, func(t *testing.T, b imageBubble) {
		requireReturned(t, lifecycleClose(b.f.s), "Close")
		b.endRequest()
		b.expire()
		retired, reads, now, usage, end := b.state()
		require(t, !retired && end == nil && b.inst.ctx.Err() != nil && now.After(b.inst.deadline) && usage == imageUsage(1, 1, 1, 1, 0),
			"before the request: retired=%v end=%v ctx err=%v now %v D %v usage %v, want the ended instance unretired", retired, end, b.inst.ctx.Err(), now, b.inst.deadline, usage)
		requireQueryResult(t, b.f.request(b.round, context.Background(), 0, 2), consensus.UTXOImageQuery{}, errServiceClosed, "request after close")
		retired, after, _, usage, end := b.state()
		require(t, !retired && end == nil && after == reads && usage == imageUsage(1, 1, 1, 1, 0) && b.f.instance(1) == b.inst,
			"after the refusal: retired=%v end=%v clock reads %d->%d usage %v, want the ended instance unretired and the clock unread", retired, end, reads, after, usage)
	})
}

type imagePassRefusal struct {
	name    string
	want    error
	drop    imageDrop
	prepare func(t *testing.T, f *imageTestFixture, ended *ImageRound, t0 time.Time) (*ImageRound, int, byte)
}

func imagePassRefusals() []imagePassRefusal {
	return []imagePassRefusal{
		{"now at the round deadline", errImageRoundDeadline, imageDrop{1, 1, 1}, func(_ *testing.T, f *imageTestFixture, ended *ImageRound, t0 time.Time) (*ImageRound, int, byte) {
			f.clock.set(t0.Add(time.Hour))
			return ended, 0, 2
		}},
		{"attempt deadline not representable", errImagePolicy, imageDrop{0, 0, 1}, func(t *testing.T, f *imageTestFixture, _ *ImageRound, t0 time.Time) (*ImageRound, int, byte) {
			limits := imageTestLimits()
			limits.AttemptLifetime = math.MaxInt64
			other := f.round(t, limits, 0)
			f.clock.set(t0.Add(50*time.Millisecond + time.Nanosecond))
			return other, 0, 2
		}},
		{"current assignment of the start", errImageAssignmentCurrent, imageDrop{0, 0, 1}, func(t *testing.T, f *imageTestFixture, _ *ImageRound, t0 time.Time) (*ImageRound, int, byte) {
			holder := f.round(t, imageTestLimits(), 1)
			f.admitted(t, holder, context.Background(), 1, 2, 1)
			f.clock.set(t0.Add(50*time.Millisecond + time.Nanosecond))
			return holder, 1, 2
		}},
		{"start attempted on the session", errImageAttempted, imageDrop{1, 1, 1}, func(_ *testing.T, f *imageTestFixture, ended *ImageRound, t0 time.Time) (*ImageRound, int, byte) {
			f.clock.set(t0.Add(50*time.Millisecond + time.Nanosecond))
			return ended, 0, 1
		}},
		{"source attempts limit", errImageLimit, imageDrop{1, 1, 1}, func(_ *testing.T, f *imageTestFixture, ended *ImageRound, t0 time.Time) (*ImageRound, int, byte) {
			f.clock.set(t0.Add(50*time.Millisecond + time.Nanosecond))
			return ended, 0, 2
		}},
		{"request id space exhausted", errImageIDExhausted, imageDrop{0, 1, 1}, func(_ *testing.T, f *imageTestFixture, ended *ImageRound, t0 time.Time) (*ImageRound, int, byte) {
			f.setLastID(1, 18446744073709551615)
			f.clock.set(t0.Add(50*time.Millisecond + time.Nanosecond))
			return ended, 1, 2
		}},
	}
}

// testImageRefusalKeepsPass admits an instance whose deadline timer has already read the clock
// short of D, moves the clock past D and checks that a request refused after the pass returns
// its refusal while the pass's retirement of that instance, recorded as errImageExpired with
// only its round's current assignment released, stays.
func testImageRefusalKeepsPass(t *testing.T) {
	for _, tc := range imagePassRefusals() {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixtureAt(t, 2, time.Now())
			t0 := f.clock.Now()
			limits := imageTestLimits()
			limits.AttemptLifetime = 50 * time.Millisecond
			limits.PerPeer.SourceAttempts = 1
			ended := f.round(t, limits, 0, 1)
			inst := f.admitTimerSpent(t, ended, 0, 1, 1)
			perPeerBefore, globalBefore := f.usage(ended, 0)
			round, session, start := tc.prepare(t, f, ended, t0)
			f.refusedAfterPass(t, round, session, start, tc.want, tc.drop)
			retired, end := f.ended(inst)
			require(t, retired && end == errImageExpired, "after the refusal: retired=%v end=%v", retired, end) //nolint:errorlint // The recorded end is errImageExpired itself.
			released := imageUsage(1, 0, 0, 0, 0)
			f.requireUsage(t, ended, 0, imageMinus(perPeerBefore, released), imageMinus(globalBefore, released), "ended round usage")
			requireEqual(t, f.lastID(0), uint64(1), "session 0 last id")
		})
	}
}

func testImageEndDuringWrite(t *testing.T) {
	writeErr := errors.New("scripted write failure")
	for _, tc := range []struct {
		name     string
		pass     bool
		writeErr error
	}{
		{"request ctx, write succeeds", false, nil},
		{"request ctx, write fails", false, writeErr},
		{"expiry by another session's pass, write succeeds", true, nil},
		{"expiry by another session's pass, write fails", true, writeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0 := f.clock.Now()
			limits := imageTestLimits()
			limits.PerPeer.PendingNetworkBytes = 120
			round := f.round(t, limits, 0, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stall := f.wires[0].armStall()
			pending := f.goRequest(round, ctx, 0, 1)
			requireChannelClosed(t, stall.entered, "request write")
			inst := f.instance(1)
			wantEnd, globalDuring := error(context.Canceled), imageUsage(0, 1, 1, 1, 120)
			if tc.pass {
				wantEnd, globalDuring = errImageExpired, imageUsage(1, 1, 2, 2, 120)
				f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
				f.admitted(t, round, context.Background(), 1, 1, 1)
			} else {
				cancel()
			}
			end := f.waitRetired(t, inst, "end during the write")
			require(t, end == wantEnd, "recorded end=%v want %v", end, wantEnd) //nolint:errorlint // The recorded end is the ctx's Err() or errImageExpired itself.
			f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 120), globalDuring, "during the write")
			f.refused(t, round, context.Background(), 0, 2, errImageLimit)
			if !tc.pass {
				f.admitted(t, round, context.Background(), 1, 1, 1)
			}
			stall.release <- tc.writeErr
			requireImageResult(t, awaitImageResult(t, pending, "written request"), 1, 1, nil, "after the write")
			wantCloses, wantLastError := 0, ""
			if tc.writeErr != nil {
				wantCloses, wantLastError = 1, tc.writeErr.Error()
			}
			requireEqual(t, f.closes(0), wantCloses, "session closes")
			lastError, _ := f.peerFault(0)
			requireEqual(t, lastError, wantLastError, "session last error")
			_, end = f.ended(inst)
			require(t, end == wantEnd, "recorded end after the write=%v", end) //nolint:errorlint // The recorded end is the ctx's Err() or errImageExpired itself.
			f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after the write")
			var written []consensus.UTXOImageQuery
			if tc.writeErr == nil {
				written = append(written, expectedImageQuery(1, 1))
			}
			f.requireFrames(t, 0, "after the write", written...)
			if tc.writeErr != nil {
				f.failedOnClosed(t, round, 0, 2, 2)
				return
			}
			f.admitted(t, round, context.Background(), 0, 2, 2)
		})
	}
	t.Run("round ctx canceled during the write", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		roundCtx, cancelRound := context.WithCancel(context.Background())
		round := f.roundCtx(t, roundCtx, imageTestLimits(), 0)
		stall := f.wires[0].armStall()
		pending := f.goRequest(round, context.Background(), 0, 1)
		requireChannelClosed(t, stall.entered, "request write")
		inst := f.instance(1)
		cancelRound()
		end := f.waitRetired(t, inst, "round ctx end")
		require(t, end == context.Canceled, "recorded end=%v", end) //nolint:errorlint // The recorded end is the round ctx's Err() itself.
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 120), imageUsage(0, 1, 1, 1, 120), "during the write")
		stall.release <- nil
		requireImageResult(t, awaitImageResult(t, pending, "written request"), 1, 1, nil, "after the write")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "after the write")
		f.requireFrames(t, 0, "round ctx end", expectedImageQuery(1, 1))
	})
}

// testImageFrameWriteDeadline checks that the recorded write deadlines of the request frame lie
// within the 15 s frame budget of the wall reads around Request. D lies before the wall read
// ahead of Request plus 15 s in both inputs, and RD and both ctx deadlines do in the second, so
// a write deadline taken from one of them is recorded earlier than that bound.
func testImageFrameWriteDeadline(t *testing.T) {
	for _, tc := range []struct {
		name          string
		roundLifetime time.Duration
		ctxTimeout    time.Duration
	}{
		{"attempt lifetime 1 s", time.Hour, 0},
		{"attempt lifetime 1 s, round lifetime 2 s and ctx deadlines in 10 s", 2 * time.Second, 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixtureAt(t, 1, time.Now())
			limits := imageTestLimits()
			limits.AttemptLifetime, limits.RoundLifetime = time.Second, tc.roundLifetime
			roundCtx, ctx := context.Background(), context.Background()
			if tc.ctxTimeout != 0 {
				var cancelRound, cancel context.CancelFunc
				roundCtx, cancelRound = context.WithTimeout(context.Background(), tc.ctxTimeout)
				defer cancelRound()
				ctx, cancel = context.WithTimeout(context.Background(), tc.ctxTimeout)
				defer cancel()
			}
			round := f.roundCtx(t, roundCtx, limits, 0)
			before := time.Now()
			got := f.request(round, ctx, 0, 1)
			after := time.Now()
			requireImageResult(t, got, 1, 1, nil, "written request")
			f.conns[0].mu.Lock()
			deadlines := append([]time.Time(nil), f.conns[0].deadlines...)
			f.conns[0].mu.Unlock()
			require(t, len(deadlines) > 0, "no write deadline recorded")
			for _, deadline := range deadlines {
				require(t, !deadline.Before(before.Add(15*time.Second)) && !deadline.After(after.Add(15*time.Second)), "write deadline %v outside [%v, %v] plus 15 s", deadline, before, after)
			}
		})
	}
}

func testImageCallbacksAndTimer(t *testing.T) {
	t.Run("round ctx", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		roundCtx, cancelRound := context.WithCancel(context.Background())
		round := f.roundCtx(t, roundCtx, imageTestLimits(), 0)
		f.admitted(t, round, context.Background(), 0, 1, 1)
		inst := f.instance(1)
		cancelRound()
		end := f.waitRetired(t, inst, "round ctx callback")
		require(t, end == context.Canceled, "end=%v", end) //nolint:errorlint // The recorded end is the round ctx's Err() itself.
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "round ctx callback")
	})
	t.Run("request ctx after the request returned", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		round := f.round(t, imageTestLimits(), 0)
		ctx, cancel := context.WithCancel(context.Background())
		f.admitted(t, round, ctx, 0, 1, 1)
		inst := f.instance(1)
		cancel()
		end := f.waitRetired(t, inst, "request ctx callback")
		require(t, end == context.Canceled, "end=%v", end) //nolint:errorlint // The recorded end is the Request ctx's Err() itself.
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "request ctx callback")
	})
	for _, tc := range []struct {
		name                   string
		attempt, roundLifetime time.Duration
	}{
		{"deadline timer with D set by the attempt lifetime", 100 * time.Millisecond, time.Hour},
		{"deadline timer with D set by the round deadline", time.Hour, 30*time.Minute + 100*time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) { testImageDeadlineTimer(t, tc.attempt, tc.roundLifetime) })
	}
	t.Run("deadline timer with D the largest duration after now", testImageSaturatedTimer)
	t.Run("deadline timer fires 1 ns after D", testImageTimerTick)
	t.Run("a ctx callback or the deadline timer refused a lease after close changes nothing", testImageCallbackOrTimerAfterClose)
	t.Run("a ctx callback or the deadline timer triggered after retirement does not run", testImageRetirementStops)
	t.Run("deadline timer with now not after D", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		limits := imageTestLimits()
		limits.AttemptLifetime = 50 * time.Millisecond
		round := f.round(t, limits, 0)
		inst := f.admitTimerSpent(t, round, 0, 1, 1)
		f.requireNoClockRead(t, "clock reads after the timer did nothing")
		require(t, f.instance(1) == inst, "timer retired a current instance")
	})
}

// testImageDeadlineTimer admits an instance 30 minutes after its round began, with D 100 ms after
// the admission's now. The clock stays at that now until Request returns and then follows real
// time from the admission read; peersMu, taken at the admission read, is released only after that
// switch, so the deadline timer reads the clock after it, no earlier than the real time the timer
// fires. With no further call, the instance retires with errImageExpired.
func testImageDeadlineTimer(t *testing.T, attempt, roundLifetime time.Duration) {
	f := newImageTestFixture(t, 1)
	limits := imageTestLimits()
	limits.AttemptLifetime, limits.RoundLifetime = attempt, roundLifetime
	round := f.round(t, limits, 0)
	t0 := f.clock.add(30 * time.Minute)
	var admittedAt time.Time
	held := false
	defer func() {
		if held {
			f.s.peersMu.Unlock()
		}
	}()
	f.clock.onNextRead(func(now time.Time) time.Time {
		for until := time.Now().Add(lifecycleWatchdog); !held && time.Now().Before(until); {
			if held = f.s.peersMu.TryLock(); !held {
				time.Sleep(time.Millisecond)
			}
		}
		admittedAt = time.Now()
		return now
	})
	f.admitted(t, round, context.Background(), 0, 1, 1)
	require(t, held, "peersMu not taken at the admission read within %s", lifecycleWatchdog)
	inst := f.instance(1)
	require(t, inst.deadline.Equal(t0.Add(100*time.Millisecond)), "D=%v, want %v", inst.deadline, t0.Add(100*time.Millisecond))
	f.clock.followRealTime(admittedAt)
	held = false
	f.s.peersMu.Unlock()
	end := f.waitRetired(t, inst, "deadline timer")
	require(t, end == errImageExpired, "end=%v", end) //nolint:errorlint // The recorded end is errImageExpired itself.
	f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "deadline timer")
}

// imageBubble is one instance admitted inside a synctest bubble on session 0 with ID 1, start 1 and
// AttemptLifetime 100 ms, through a round with a cancellable round ctx and a cancellable Request
// ctx. The bubble's fake clock moves only while the bubble's goroutines are durably blocked.
type imageBubble struct {
	f                          *imageTestFixture
	round                      *ImageRound
	inst                       *imageInstance
	t0                         time.Time
	cancelRequest, cancelRound context.CancelFunc
}

// runImageBubble runs body on an imageBubble. With follow set, the controlled clock follows the
// bubble's fake clock from the admission on, so the admission reads t0 and the deadline timer
// reads t0 plus the fake time elapsed when it fires.
func runImageBubble(t *testing.T, follow bool, body func(t *testing.T, b imageBubble)) {
	synctest.Test(t, func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		t0 := f.clock.Now()
		limits := imageTestLimits()
		limits.AttemptLifetime = 100 * time.Millisecond
		roundCtx, cancelRound := context.WithCancel(context.Background())
		defer cancelRound()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		round := f.roundCtx(t, roundCtx, limits, 0)
		if follow {
			f.clock.followRealTime(time.Now())
		}
		f.admitted(t, round, ctx, 0, 1, 1)
		body(t, imageBubble{f, round, f.instance(1), t0, cancel, cancelRound})
	})
}

// expire moves the controlled clock 1 ns past D, then runs passTimer.
func (b imageBubble) expire() {
	b.f.clock.set(b.t0.Add(100*time.Millisecond + time.Nanosecond))
	b.passTimer()
}

// passTimer lets the bubble's fake clock pass the deadline timer's duration, then returns after
// synctest.Wait.
func (b imageBubble) passTimer() {
	time.Sleep(time.Second)
	synctest.Wait()
}

// state returns whether the instance is retired, the controlled clock's read count and last value,
// the round's usage on session 0 and the instance's recorded end.
func (b imageBubble) state() (bool, int, time.Time, imageUnitVector, error) {
	retired, end := b.f.ended(b.inst)
	perPeer, _ := b.f.usage(b.round, 0)
	b.f.clock.mu.Lock()
	defer b.f.clock.mu.Unlock()
	return retired, b.f.clock.reads, b.f.clock.now, perPeer, end
}

// testImageTimerTick admits an instance with D 100 ms after the admission's now and lets the fake
// clock run: the deadline timer fires exactly its duration after admission, reads the clock once
// at D plus 1 ns and retires the instance with errImageExpired.
func testImageTimerTick(t *testing.T) {
	runImageBubble(t, true, func(t *testing.T, b imageBubble) {
		_, reads, _, _, _ := b.state()
		b.passTimer()
		retired, after, last, usage, end := b.state()
		want := b.t0.Add(100*time.Millisecond + time.Nanosecond)
		require(t, retired && end == errImageExpired && after == reads+1 && last.Equal(want) && usage == imageUsage(0, 1, 1, 1, 0), //nolint:errorlint // The recorded end is errImageExpired itself.
			"deadline timer: retired=%v end=%v clock reads %d->%d last read %v usage %v, want retired with %v after one read at %v", retired, end, reads, after, last, usage, errImageExpired, want)
	})
}

// testImageCallbackOrTimerAfterClose closes the Service with an instance still current, then
// starts one of the Request ctx callback, the round ctx callback and the deadline timer, with the
// controlled clock left at the admission's now, short of D: it cancels the Request ctx or the
// round ctx, or lets the fake clock pass the timer's duration. The started callback or timer is
// refused a lease and returns without reading the clock, retiring or releasing anything, and its
// stop handle reports that it had started.
func testImageCallbackOrTimerAfterClose(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger func(b imageBubble)
		stop    func(inst *imageInstance) bool
	}{
		{"request ctx callback", imageBubble.endRequest, func(inst *imageInstance) bool { return inst.stopCtx() }},
		{"round ctx callback", imageBubble.endRound, func(inst *imageInstance) bool { return inst.stopRound() }},
		{"deadline timer", imageBubble.passTimer, func(inst *imageInstance) bool { return inst.timer.Stop() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runImageBubble(t, false, func(t *testing.T, b imageBubble) {
				requireReturned(t, lifecycleClose(b.f.s), "Close")
				_, reads, _, _, _ := b.state()
				tc.trigger(b)
				retired, after, now, usage, end := b.state()
				require(t, !retired && end == nil && after == reads && now.Equal(b.t0) && usage == imageUsage(1, 1, 1, 1, 0) && b.f.instance(1) == b.inst,
					"callback or timer after close: retired=%v end=%v clock reads %d->%d now %v usage %v, want the instance current at %v and no clock read", retired, end, reads, after, now, usage, b.t0)
				req := b.f.lockRequester()
				stopped := tc.stop(b.inst)
				req.mu.Unlock()
				require(t, !stopped, "callback or timer after close: its stop handle stopped it, want it started before")
			})
		})
	}
}

// testImageRetirementStops retires the instance through one ctx callback, then triggers the other
// ctx callback or the deadline timer: retirement stopped it, so it does not run and the clock is
// not read again.
func testImageRetirementStops(t *testing.T) {
	for _, tc := range []struct {
		name          string
		retire, later func(b imageBubble)
		end           error
	}{
		{"deadline timer after a request ctx end", imageBubble.endRequest, imageBubble.expire, context.Canceled},
		{"round ctx callback after a request ctx end", imageBubble.endRequest, imageBubble.endRound, context.Canceled},
		{"request ctx callback after a round ctx end", imageBubble.endRound, imageBubble.endRequest, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runImageBubble(t, false, func(t *testing.T, b imageBubble) {
				tc.retire(b)
				retired, reads, _, usage, end := b.state()
				require(t, retired && end == tc.end && usage == imageUsage(0, 1, 1, 1, 0), "first end: retired=%v end=%v usage %v, want retired with %v", retired, end, usage, tc.end) //nolint:errorlint // The recorded end is the first end's ctx error itself.
				tc.later(b)
				_, after, _, _, end := b.state()
				require(t, after == reads && end == tc.end, "callback or timer after retirement: clock reads %d->%d end %v, want no read and the end %v kept", reads, after, end, tc.end) //nolint:errorlint // The kept end is the first end's ctx error itself.
			})
		})
	}
}

// endRequest cancels the Request ctx and endRound the round ctx; both then return after
// synctest.Wait.
func (b imageBubble) endRequest() {
	b.cancelRequest()
	synctest.Wait()
}

func (b imageBubble) endRound() {
	b.cancelRound()
	synctest.Wait()
}

// testImageSaturatedTimer admits an instance whose D is the largest Duration after the
// admission's now on a wall-only clock; its deadline timer does not fire within lifecycleSettle,
// so the clock is not read again and the instance stays current.
func testImageSaturatedTimer(t *testing.T) {
	f := newImageTestFixture(t, 1)
	t0 := f.clock.Now()
	limits := imageTestLimits()
	limits.AttemptLifetime, limits.RoundLifetime = math.MaxInt64, math.MaxInt64
	round := f.round(t, limits, 0)
	f.admitted(t, round, context.Background(), 0, 1, 1)
	inst := f.instance(1)
	require(t, inst.deadline.Sub(t0) == math.MaxInt64, "D-now=%v, want the largest Duration", inst.deadline.Sub(t0))
	f.requireNoClockRead(t, "clock reads after the request")
	retired, _ := f.ended(inst)
	require(t, !retired && f.instance(1) == inst, "instance with a saturated deadline timer: retired=%v", retired)
}

// admitTimerSpent admits start on session through round, with D a short real time after now and
// writeMu free, and waits until the clock, which does not move, has been read three times: the
// admission read first, then the pre-write read and the deadline timer's read in either order,
// since commitLocked arms the timer after the admission read. The three reads find now not after D. Under
// the requester mutex, which the timer holds across its read, the instance is unretired and
// stopping its timer reports that the timer had already fired and was not armed again.
func (f *imageTestFixture) admitTimerSpent(t *testing.T, round *ImageRound, session int, start byte, wantID uint64) *imageInstance {
	t.Helper()
	reads := f.clock.readCount()
	f.admitted(t, round, context.Background(), session, start, wantID)
	waitUntil(t, func() bool { return f.clock.readCount() >= reads+3 }, "deadline timer read")
	inst := f.instance(start)
	require(t, inst != nil, "start %d has no current instance after its timer read", start)
	req := f.lockRequester()
	retired, end, rearmed := inst.retired, inst.end, inst.timer.Stop()
	req.mu.Unlock()
	require(t, !retired && !rearmed, "timer with now not after D: retired=%v end=%v, timer armed again=%v", retired, end, rearmed)
	requireEqual(t, f.clock.readCount(), reads+3, "clock reads after the timer read")
	return inst
}

func (f *imageTestFixture) onClose(session int, hook func()) {
	var once sync.Once
	conn := f.conns[session]
	conn.mu.Lock()
	conn.closeHook = func() { once.Do(hook) }
	conn.mu.Unlock()
}

func testImageFailedWrite(t *testing.T) {
	t.Run("connection closed after the instance retires", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		round := f.round(t, imageTestLimits(), 0, 1)
		var inHook imageResult
		// The hook runs inside the failed request, whose own bound is lifecycleWatchdog.
		f.onClose(0, func() {
			inHook = requestWithin(lifecycleWatchdog/2, round, context.Background(), f.ids[1], 1, imageTestByteLimit)
		})
		stall := f.wires[0].armStall()
		stall.release <- os.ErrDeadlineExceeded
		got := f.request(round, context.Background(), 0, 1)
		requireChannelClosed(t, stall.entered, "connection write that fails with the scripted error")
		requireImageResult(t, got, 1, 1, os.ErrDeadlineExceeded, "failed write")
		require(t, !errors.Is(got.err, errImageExpired), "write failure reported as expiry: %v", got.err)
		closes := f.closes(0)
		lastError, _ := f.peerFault(0)
		require(t, closes == 1 && lastError == os.ErrDeadlineExceeded.Error() && inHook.q == expectedImageQuery(1, 1) && inHook.err == nil,
			"after the failed write: closes=%d last error %q, request in the close hook q=%+v err=%v; want 1 close, last error %q and id 1 start 1 with nil", closes, lastError, inHook.q, inHook.err, os.ErrDeadlineExceeded.Error())
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after the failed write")
		f.failedOnClosed(t, round, 0, 2, 2)
		f.requireFrames(t, 0, "after the failure")
	})
	t.Run("sibling stays current", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		round := f.round(t, imageTestLimits(), 0, 1)
		f.admitted(t, round, context.Background(), 0, 1, 1)
		sendErr := errors.New("scripted write failure")
		f.wires[0].armStall().release <- sendErr
		requireImageResult(t, f.request(round, context.Background(), 0, 2), 2, 2, sendErr, "failed write")
		f.requireUsage(t, round, 0, imageUsage(1, 2, 2, 2, 0), imageUsage(1, 2, 2, 2, 0), "after the failed write")
		f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
		f.admitted(t, round, context.Background(), 1, 2, 1)
		f.failedOnClosed(t, round, 0, 3, 3)
		f.requireFrames(t, 0, "session frames", expectedImageQuery(1, 1))
		f.requireUsage(t, round, 0, imageUsage(1, 3, 3, 3, 0), imageUsage(2, 3, 4, 4, 0), "after the later requests")
	})
}

func testImageStaleHandle(t *testing.T) {
	t.Run("a ctx callback started before a pass retired its instance runs after the replacement", testImageStaleCallback)
	t.Run("write failure of an instance ended during the write", func(t *testing.T) {
		f := newImageTestFixture(t, 3)
		t0 := f.clock.Now()
		round := f.round(t, imageTestLimits(), 0, 1, 2)
		stall := f.wires[0].armStall()
		pending := f.goRequest(round, context.Background(), 0, 1)
		requireChannelClosed(t, stall.entered, "request write")
		f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
		f.admitted(t, round, context.Background(), 1, 1, 1)
		replacement := f.instance(1)
		stall.release <- errors.New("scripted write failure")
		requireImageResult(t, awaitImageResult(t, pending, "failed write"), 1, 1, nil, "failed write after an end")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after the failed write")
		f.refused(t, round, context.Background(), 2, 1, errImageAssignmentCurrent)
		require(t, f.instance(1) == replacement, "replacement retired by a stale write failure")
	})
}

// testImageStaleCallback cancels the first instance's ctx inside the admission clock read of a
// request for the same start on another session. That request holds the requester mutex across
// the read, so the launched ctx callback takes the mutex only after the request's pass retired
// the first instance and the replacement was registered. The two clock reads after the hook's
// are the replacement's pre-write read and the callback's read, in either order; both deadline
// timers have the largest Duration, so neither reads the clock.
func testImageStaleCallback(t *testing.T) {
	f := newImageTestFixture(t, 3)
	limits := imageTestLimits()
	limits.AttemptLifetime, limits.RoundLifetime = math.MaxInt64, math.MaxInt64
	round := f.round(t, limits, 0, 1, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.admitted(t, round, ctx, 0, 1, 1)
	stale := f.instance(1)
	f.clock.cancelOnRead(cancel)
	f.admitted(t, round, context.Background(), 1, 1, 1)
	f.awaitReadsAfterHook(t, 2, "stale ctx callback")
	f.refused(t, round, context.Background(), 2, 1, errImageAssignmentCurrent)
	replacement := f.instance(1)
	require(t, replacement != nil && replacement != stale && replacement.session == f.peers[1], "current instance after the stale callback: %p, want the replacement on session 1", replacement)
	retired, _ := f.ended(replacement)
	_, end := f.ended(stale)
	require(t, !retired && end == context.Canceled, "replacement retired=%v, stale end=%v", retired, end) //nolint:errorlint // The stale instance keeps its ctx's Err() itself.
	f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after the stale callback")
}

func (f *imageTestFixture) requireRoundRefused(t *testing.T, ctx context.Context, config ImageRoundConfig, want error, label string) {
	t.Helper()
	round, err := f.begin(ctx, config)
	require(t, round == nil && err == want, "%s: round=%v err=%v want %v", label, round != nil, err, want) //nolint:errorlint // The refusal is the wanted sentinel itself, not a wrapper.
}

func testImageRoundRefusals(t *testing.T) {
	f := newImageTestFixture(t, 2)
	type refusal struct {
		name   string
		mutate func(*ImageRoundConfig)
		want   error
	}
	cases := []refusal{
		{"anchor height above the request domain", func(c *ImageRoundConfig) { c.Anchor.Height = 0x100000000 }, errImageRequestDomain},
		{"anchor height at the uint64 maximum", func(c *ImageRoundConfig) { c.Anchor.Height = math.MaxUint64 }, errImageRequestDomain},
		{"zero attempt lifetime", func(c *ImageRoundConfig) { c.Limits.AttemptLifetime = 0 }, errImagePolicy},
		{"negative attempt lifetime", func(c *ImageRoundConfig) { c.Limits.AttemptLifetime = -time.Nanosecond }, errImagePolicy},
		{"zero round lifetime", func(c *ImageRoundConfig) { c.Limits.RoundLifetime = 0 }, errImagePolicy},
		{"negative round lifetime", func(c *ImageRoundConfig) { c.Limits.RoundLifetime = -time.Second }, errImagePolicy},
		{"zero backoff", func(c *ImageRoundConfig) { c.Limits.Backoff = 0 }, errImagePolicy},
		{"negative backoff", func(c *ImageRoundConfig) { c.Limits.Backoff = -time.Nanosecond }, errImagePolicy},
		{"nil source list", func(c *ImageRoundConfig) { c.SourceIDs = nil }, errImageSourceSet},
		{"empty non-nil source list", func(c *ImageRoundConfig) { c.SourceIDs = []string{} }, errImageSourceSet},
		{"source with no service entry", func(c *ImageRoundConfig) { c.SourceIDs = []string{"absent:1"} }, errImageSourceSet},
		{"source with no service entry after a resolved source", func(c *ImageRoundConfig) { c.SourceIDs = []string{f.ids[0], "absent:1"} }, errImageSourceSet},
		{"same source twice", func(c *ImageRoundConfig) { c.SourceIDs = []string{f.ids[0], f.ids[0]} }, errImageSourceSet},
		{"logical address and its alias", func(c *ImageRoundConfig) { c.SourceIDs = []string{f.ids[0], "192.0.2.40:9"} }, errImageSourceSet},
		{"alias and its logical address", func(c *ImageRoundConfig) { c.SourceIDs = []string{"192.0.2.40:9", f.ids[0]} }, errImageSourceSet},
		{"nil ctx with height above the domain", func(c *ImageRoundConfig) { c.Anchor.Height = 0x100000000 }, errImageNilContext},
		{"height above the domain with zero backoff", func(c *ImageRoundConfig) { c.Anchor.Height, c.Limits.Backoff = 0x100000000, 0 }, errImageRequestDomain},
		{"zero backoff with empty sources", func(c *ImageRoundConfig) { c.Limits.Backoff, c.SourceIDs = 0, nil }, errImagePolicy},
	}
	fields := reflect.TypeFor[ImageUnits]()
	for i := range fields.NumField() {
		zero := func(u *ImageUnits) { reflect.ValueOf(u).Elem().Field(i).SetUint(0) }
		cases = append(cases,
			refusal{"zero per-peer " + fields.Field(i).Name, func(c *ImageRoundConfig) { zero(&c.Limits.PerPeer) }, errImagePolicy},
			refusal{"zero global " + fields.Field(i).Name, func(c *ImageRoundConfig) { zero(&c.Limits.Global) }, errImagePolicy})
	}
	for _, tc := range cases {
		config := f.config(imageTestLimits(), 0, 1)
		tc.mutate(&config)
		ctx := context.Background()
		if errors.Is(tc.want, errImageNilContext) {
			ctx = nil
		}
		f.requireRoundRefused(t, ctx, config, tc.want, tc.name)
	}
	late := newImageTestFixtureAt(t, 1, time.Unix(imageMaxWall, 999999999).Add(-time.Hour))
	unknown := late.config(imageTestLimits(), 0)
	unknown.SourceIDs, unknown.Limits.RoundLifetime = []string{"absent:1"}, 2*time.Hour
	late.requireRoundRefused(t, context.Background(), unknown, errImageSourceSet, "unknown source with an unrepresentable RD")
	for _, fixture := range []struct {
		name string
		f    *imageTestFixture
	}{{"listed refusals", f}, {"unknown source with an unrepresentable RD", late}} {
		req := fixture.f.s.imageRequester
		require(t, len(req.lastID) == 0 && len(req.current) == 0, "%s left registry state: %d last ids, %d current", fixture.name, len(req.lastID), len(req.current))
	}
}

func testImageRoundAdmits(t *testing.T) {
	f := newImageTestFixture(t, 1)
	passing := f.config(ImageLimits{PerPeer: imageTestUnits(math.MaxUint64), Global: imageTestUnits(math.MaxUint64), AttemptLifetime: time.Second, RoundLifetime: time.Hour, Backoff: time.Second}, 0)
	passing.Anchor.Height = 0xffffffff
	round, err := f.begin(context.Background(), passing)
	require(t, round != nil && err == nil, "height 0xffffffff and uint64 max limits: err=%v", err)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	done := f.roundCtx(t, canceled, imageTestLimits(), 0)
	f.refused(t, done, context.Background(), 0, 1, context.Canceled)
	f.admitted(t, f.round(t, imageTestLimits(), 0), context.Background(), 0, 1, 1)
}

func testImageRequestRefusals(t *testing.T) {
	t.Run("checks before the registry", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		round := f.round(t, imageTestLimits(), 0)
		var nilCtx context.Context
		f.refused(t, round, nilCtx, 0, 1, errImageNilContext)
		f.refusedWith(t, round, context.Background(), f.ids[1], 0, 1, imageTestByteLimit, errImageUnknownSource)
		f.refusedWith(t, round, context.Background(), "absent:1", 0, 1, imageTestByteLimit, errImageUnknownSource)
		f.refusedWith(t, round, context.Background(), f.ids[1], 0, 1, 150904, errImageUnknownSource)
		for _, limit := range []uint32{0, 150904, 2097153, math.MaxUint32} {
			f.refusedWith(t, round, context.Background(), f.ids[0], 0, 1, limit, errImageRequestDomain)
		}
		expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
		defer cancelExpired()
		done := f.roundCtx(t, expired, imageTestLimits(), 0)
		f.refusedWith(t, done, context.Background(), "absent:1", 0, 1, imageTestByteLimit, context.DeadlineExceeded)
		var written []consensus.UTXOImageQuery
		for i, limit := range []uint32{150905, 2097152} {
			want := expectedImageQuery(uint64(i+1), byte(limit))
			want.ByteLimit = limit
			got := requestWithin(lifecycleWatchdog, round, context.Background(), f.ids[0], byte(limit), limit)
			requireQueryResult(t, got, want, nil, fmt.Sprintf("byte limit %d", limit))
			written = append(written, want)
		}
		f.requireFrames(t, 0, "byte limits at the domain bounds", written...)
	})
	t.Run("byte limit, round deadline, assignment, attempt, limit and id checks in order", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		t0 := f.clock.Now()
		limits := imageTestLimits()
		limits.PerPeer.AdmittedRequests = 2
		round := f.round(t, limits, 0, 1)
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.refused(t, round, context.Background(), 0, 1, errImageAssignmentCurrent)
		f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
		ctx, cancel := context.WithCancel(context.Background())
		f.admitted(t, round, ctx, 0, 2, 2)
		inst := f.instance(2)
		cancel()
		f.waitRetired(t, inst, "canceled instance")
		f.refused(t, round, context.Background(), 0, 2, errImageAttempted)
		f.refused(t, round, context.Background(), 0, 3, errImageLimit)
		f.setLastID(1, 18446744073709551615)
		f.refused(t, round, context.Background(), 1, 3, errImageIDExhausted)
		tight := imageTestLimits()
		tight.PerPeer.PendingNetworkBytes = 119
		f.refused(t, f.round(t, tight, 1), context.Background(), 1, 4, errImageLimit)
		f.clock.set(t0.Add(time.Hour))
		f.refusedWith(t, round, context.Background(), f.ids[0], 0, 5, 2097153, errImageRequestDomain)
		f.refusedAfterPass(t, round, 0, 5, errImageRoundDeadline, imageDrop{1, 1, 1})
	})
	t.Run("done contexts refuse before admission", testImageDoneContexts)
	t.Run("a ctx done at the admission clock read refuses ahead of the pass", testImageDoneAtAdmissionRead)
	t.Run("round deadline and attempt deadline", func(t *testing.T) {
		base := time.Now()
		f := newImageTestFixtureAt(t, 2, base)
		long := imageTestLimits()
		long.AttemptLifetime, long.RoundLifetime = time.Hour, 2*time.Hour
		holder := f.round(t, long, 0)
		short := imageTestLimits()
		short.AttemptLifetime, short.RoundLifetime = math.MaxInt64, 10*time.Second
		unrepresentable := f.round(t, short, 1)
		f.admitted(t, holder, context.Background(), 0, 1, 1)
		f.refused(t, unrepresentable, context.Background(), 1, 1, errImagePolicy)
		f.clock.set(base.Add(10 * time.Second))
		f.refused(t, unrepresentable, context.Background(), 1, 1, errImageRoundDeadline)
		f.refused(t, unrepresentable, context.Background(), 1, 2, errImageRoundDeadline)
	})
}

func testImageRepresentability(t *testing.T) {
	maxWall := time.Unix(imageMaxWall, 999999999)
	f := newImageTestFixture(t, 1)
	f.clock.set(maxWall.Add(-time.Hour))
	limits := imageTestLimits()
	limits.AttemptLifetime, limits.RoundLifetime = time.Hour, time.Hour
	round := f.round(t, limits, 0)
	require(t, round.roundDeadline.Equal(maxWall), "RD=%v want the wall maximum", round.roundDeadline)
	limits.RoundLifetime = time.Hour + time.Nanosecond
	f.requireRoundRefused(t, context.Background(), f.config(limits, 0), errImagePolicy, "saturated RD")
	limits.RoundLifetime, limits.AttemptLifetime = time.Hour, time.Hour+time.Nanosecond
	f.refused(t, f.round(t, limits, 0), context.Background(), 0, 1, errImagePolicy)
	f.admitted(t, round, context.Background(), 0, 1, 1)
	monotonic := newImageTestFixtureAt(t, 1, time.Now())
	limits = imageTestLimits()
	limits.RoundLifetime = math.MaxInt64
	monotonic.requireRoundRefused(t, context.Background(), monotonic.config(limits, 0), errImagePolicy, "lost monotonic RD")
	limits.RoundLifetime, limits.AttemptLifetime = time.Hour, math.MaxInt64
	monotonic.refused(t, monotonic.round(t, limits, 0), context.Background(), 0, 1, errImagePolicy)
}

// serviceEntry returns the connection Service.peers names for key, or nil.
func (f *imageTestFixture) serviceEntry(key string) *peer {
	waitUntil(f.t, f.s.peersMu.TryRLock, "peersMu")
	defer f.s.peersMu.RUnlock()
	return f.s.peers[key]
}

// registeredLive reports whether p is in the Service's set of live registered connections.
func (f *imageTestFixture) registeredLive(p *peer) bool {
	waitUntil(f.t, f.s.peersMu.TryRLock, "peersMu")
	defer f.s.peersMu.RUnlock()
	_, live := f.s.livePeers[p]
	return live
}

func testImageCapturedSourceID(t *testing.T) {
	t.Run("alias of a captured source", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		owner, alias := f.serviceEntry(f.ids[0]), f.serviceEntry("192.0.2.40:9")
		require(t, owner == f.peers[0] && alias == f.peers[0], "logical address names %p and alias names %p, want session %p", owner, alias, f.peers[0])
		round := f.round(t, imageTestLimits(), 0)
		f.refusedWith(t, round, context.Background(), "192.0.2.40:9", 0, 1, imageTestByteLimit, errImageUnknownSource)
		requireEqual(t, f.closes(0), 0, "session closes")
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.requireFrames(t, 0, "logical address", expectedImageQuery(1, 1))
	})
	t.Run("newer registration of the logical address", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		owner := f.serviceEntry(f.ids[0])
		require(t, owner == f.peers[0], "logical address names %p at round construction, want session %p", owner, f.peers[0])
		round := f.round(t, imageTestLimits(), 0)
		newer := f.addSession(t, f.ids[0], "192.0.2.81:9")
		owner = f.serviceEntry(f.ids[0])
		live := f.registeredLive(f.peers[0])
		require(t, owner == f.peers[newer], "newer registration does not own the address: %p", owner)
		require(t, live && f.closes(0) == 0, "captured session after the newer registration: live=%v closes=%d", live, f.closes(0))
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.requireFrames(t, 0, "captured session", expectedImageQuery(1, 1))
		f.requireFrames(t, newer, "newer registration")
	})
}

func testImageServiceClose(t *testing.T) {
	t.Run("refusals after close", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		round := f.round(t, imageTestLimits(), 0)
		requireReturned(t, lifecycleClose(f.s), "Close")
		f.refused(t, round, context.Background(), 0, 1, errServiceClosed)
		var nilCtx context.Context
		f.refused(t, round, nilCtx, 0, 1, errServiceClosed)
		f.requireRoundRefused(t, context.Background(), f.config(imageTestLimits(), 0), errServiceClosed, "valid config")
		f.requireRoundRefused(t, nil, f.config(imageTestLimits(), 0), errServiceClosed, "nil ctx")
	})
	t.Run("request waiting for writeMu", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		t0 := f.clock.Now()
		round := f.round(t, imageTestLimits(), 0)
		release := f.holdWrite(t, 0)
		pending := f.goRequest(round, context.Background(), 0, 1)
		f.waitAdmitted(t, 0, 1, "parked request")
		inst := f.instance(1)
		f.onClose(0, func() { f.clock.set(t0.Add(10*time.Second + time.Nanosecond)) })
		// The test's own lease keeps Close from returning, so the request's result and state are
		// observed while Close has not returned.
		require(t, f.s.acquireWork(), "test lease refused")
		closed := lifecycleClose(f.s)
		requireImageResult(t, awaitImageResult(t, pending, "parked request"), 1, 1, errImageExpired, "parked request before Close returns")
		retired, end := f.ended(inst)
		require(t, retired && end == errImageExpired, "before Close returns: retired=%v end=%v", retired, end) //nolint:errorlint // The recorded end is errImageExpired itself.
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "before Close returns")
		requireStillBlocked(t, closed, "Close with the test lease held")
		f.s.releaseWork()
		requireReturned(t, closed, "Close")
		_ = release()
		f.requireFrames(t, 0, "parked request")
	})
	t.Run("request write failed by close", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		round := f.round(t, imageTestLimits(), 0)
		closers := f.recordClosers(round, 0)
		stall := f.wires[0].armStall()
		closeErr := errors.New("connection closed by close")
		pending := f.goRequest(round, context.Background(), 0, 1)
		requireChannelClosed(t, stall.entered, "request write")
		req := f.lockRequester()
		closed := lifecycleClose(f.s)
		requireChannelClosed(t, f.conns[0].closed, "connection close")
		stall.release <- closeErr
		requireStillBlocked(t, closed, "Close with the post-write section pending")
		req.mu.Unlock()
		requireReturned(t, closed, "Close")
		want := []imageCloser{{}, {request: true, lastError: closeErr.Error(), perPeer: imageUsage(0, 1, 1, 1, 0), global: imageUsage(0, 1, 1, 1, 0)}}
		got := closers()
		require(t, slices.Equal(got, want), "connection closes recorded by Close return=%+v, want %+v", got, want)
		requireEqual(t, f.closes(0), 2, "connection closes")
		lastError, _ := f.peerFault(0)
		requireEqual(t, lastError, closeErr.Error(), "session last error")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "at Close return")
		requireImageResult(t, awaitImageResult(t, pending, "failed write"), 1, 1, closeErr, "failed write")
		f.requireFrames(t, 0, "failed write")
	})
}

// imageCloser is one Close of a session connection: whether it ran inside a Request call, and,
// for one that did, the session's last error and the round's usage at that Close.
type imageCloser struct {
	request         bool
	lastError       string
	perPeer, global imageUnitVector
}

// recordClosers records every later Close of session's connection and returns the records so far.
func (f *imageTestFixture) recordClosers(round *ImageRound, session int) func() []imageCloser {
	var mu sync.Mutex
	var records []imageCloser
	p, conn := f.peers[session], f.conns[session]
	conn.mu.Lock()
	conn.closeHook = func() {
		record := imageCloser{request: imageCalledFrom(".(*ImageRound).Request")}
		if record.request {
			p.stateMu.Lock()
			record.lastError = p.state.LastError
			p.stateMu.Unlock()
			req := f.s.imageRequester
			req.mu.Lock()
			record.perPeer, record.global = *round.usageFor(p), round.global
			req.mu.Unlock()
		}
		mu.Lock()
		records = append(records, record)
		mu.Unlock()
	}
	conn.mu.Unlock()
	return func() []imageCloser {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(records)
	}
}

const imageUnwindSentinel = "image requester test unwind"

func testImageUnwind(t *testing.T) {
	t.Run("a panic in the clock read of the pre-write decision made with writeMu acquired", func(t *testing.T) { testImageUnwindWithWriteMu(t, false) })
	t.Run("runtime.Goexit in the clock read of the pre-write decision made with writeMu acquired", func(t *testing.T) { testImageUnwindWithWriteMu(t, true) })
	t.Run("a panic in a clock read made after a failed TryLock", testImageUnwindWaiting)
	t.Run("a panic in the connection write of the request frame", testImageUnwindWrite)
}

// imageUnwindLimits is imageTestLimits with 120 pending request bytes per peer and globally.
func imageUnwindLimits() ImageLimits {
	limits := imageTestLimits()
	limits.PerPeer.PendingNetworkBytes, limits.Global.PendingNetworkBytes = 120, 120
	return limits
}

// unwindAtPreWriteRead makes the first later clock read made by a pre-write decision call unwind;
// the reads before it leave the clock unchanged.
func (f *imageTestFixture) unwindAtPreWriteRead(unwind func()) {
	var hook func(time.Time) time.Time
	hook = func(now time.Time) time.Time {
		if imageCalledFrom(".(*ImageRound).endBeforeWrite") {
			unwind()
		}
		f.clock.onRead = hook
		return now
	}
	f.clock.onNextRead(hook)
}

// requestRecovered requests start on session and returns the value the call panicked with, or nil
// when it returned.
func (f *imageTestFixture) requestRecovered(t *testing.T, round *ImageRound, session int, start byte) any {
	t.Helper()
	return callWithin(t, "unwinding request", func() (recovered any) {
		defer func() { recovered = recover() }()
		_, _ = round.Request(context.Background(), f.ids[session], imageStart(start), imageTestByteLimit)
		return nil
	})
}

// requestExited requests start on session on its own goroutine and reports whether that goroutine
// ended without the call returning.
func (f *imageTestFixture) requestExited(t *testing.T, round *ImageRound, session int, start byte) bool {
	t.Helper()
	returned := false
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		_, _ = round.Request(context.Background(), f.ids[session], imageStart(start), imageTestByteLimit)
		returned = true
	}()
	requireChannelClosed(t, ended, "request goroutine end")
	return !returned
}

// requireNextAfterUnwind requests start on session and checks, within lifecycleWatchdog, the query
// with wantID and nil and then exactly one frame, for that query. The request's ctx is canceled at
// cleanup, so a request still waiting for writeMu then returns.
func (f *imageTestFixture) requireNextAfterUnwind(t *testing.T, round *ImageRound, session int, start byte, wantID uint64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	got, returned := receiveWithin(f.goRequest(round, ctx, session, start), lifecycleWatchdog)
	if returned {
		requireImageResult(t, got, wantID, start, nil, "request after the unwind")
	}
	f.requireFrames(t, session, "request after the unwind", expectedImageQuery(wantID, start))
	require(t, returned, "request after the unwind did not return within %s", lifecycleWatchdog)
}

// requireNoFaultBeforeClose checks that session's connection was not closed and has no last error,
// then that Close returns within lifecycleWatchdog.
func (f *imageTestFixture) requireNoFaultBeforeClose(t *testing.T, session int) {
	t.Helper()
	lastError, _ := f.peerFault(session)
	require(t, f.closes(session) == 0 && lastError == "", "after the unwind: closes=%d last error %q, want none", f.closes(session), lastError)
	requireReturned(t, lifecycleClose(f.s), "Close")
}

// testImageUnwindWithWriteMu unwinds the request for start 1 on session 0, with writeMu free, at
// the clock read its pre-write decision makes with writeMu acquired, by a panic or runtime.Goexit.
func testImageUnwindWithWriteMu(t *testing.T, goexit bool) {
	f := newImageTestFixture(t, 2)
	round := f.round(t, imageUnwindLimits(), 0, 1)
	f.unwindAtPreWriteRead(func() {
		if goexit {
			runtime.Goexit()
		}
		panic(imageUnwindSentinel)
	})
	if goexit {
		require(t, f.requestExited(t, round, 0, 1), "request returned instead of exiting its goroutine")
	} else {
		recovered := f.requestRecovered(t, round, 0, 1)
		require(t, recovered == imageUnwindSentinel, "recovered %v, want %q", recovered, imageUnwindSentinel)
	}
	f.requireFrames(t, 0, "after the unwind")
	f.requireNextAfterUnwind(t, round, 0, 2, 2)
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.requireNoFaultBeforeClose(t, 0)
}

// testImageUnwindWaiting holds session 0's writeMu and unwinds the request for start 1 at the
// clock read its pre-write decision makes after a failed TryLock. The next request waits for the
// writeMu the test holds and writes its frame only after the test releases it.
func testImageUnwindWaiting(t *testing.T) {
	f := newImageTestFixture(t, 1)
	round := f.round(t, imageUnwindLimits(), 0)
	session := f.peers[0]
	session.writeMu.Lock()
	held := true
	defer func() {
		if held {
			_ = session.writeMu.TryLock()
			session.writeMu.Unlock()
		}
	}()
	f.unwindAtPreWriteRead(func() { panic(imageUnwindSentinel) })
	recovered := f.requestRecovered(t, round, 0, 1)
	require(t, recovered == imageUnwindSentinel, "recovered %v, want %q", recovered, imageUnwindSentinel)
	pending := f.goRequest(round, context.Background(), 0, 2)
	f.waitAdmitted(t, 0, 2, "request after the unwind")
	_, returned := receiveWithin(pending, lifecycleSettle)
	f.requireFrames(t, 0, "while the test holds writeMu")
	require(t, !returned, "request after the unwind returned while the test held writeMu")
	held = false
	session.writeMu.Unlock()
	requireImageResult(t, awaitImageResult(t, pending, "request after the unwind"), 2, 2, nil, "request after the unwind")
	f.requireFrames(t, 0, "after the test released writeMu", expectedImageQuery(2, 2))
	requireReturned(t, lifecycleClose(f.s), "Close")
}

// testImageUnwindWrite makes the connection write of the request frame for start 1 on session 0
// panic before it records a byte.
func testImageUnwindWrite(t *testing.T) {
	f := newImageTestFixture(t, 1)
	round := f.round(t, imageUnwindLimits(), 0)
	f.wires[0].armPanic(imageUnwindSentinel)
	recovered := f.requestRecovered(t, round, 0, 1)
	require(t, recovered == imageUnwindSentinel, "recovered %v, want %q", recovered, imageUnwindSentinel)
	requireEqual(t, len(f.wires[0].bytes()), 0, "bytes written by the panicking write")
	f.requireNextAfterUnwind(t, round, 0, 2, 2)
	f.requireNoFaultBeforeClose(t, 0)
}
