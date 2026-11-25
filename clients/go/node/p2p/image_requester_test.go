package p2p

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
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

// imageTestClock is a controlled ServiceConfig.Now, safe for concurrent reads, that counts them.
// onRead runs once on the next read and its result becomes the clock's time; after followRealTime
// each read first moves the clock by the real time elapsed. A move back fails the test.
type imageTestClock struct {
	t        *testing.T
	mu       sync.Mutex
	now      time.Time
	reads    int
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
		c.onRead = nil
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

// inImageBubble runs body in its own synctest bubble, where synctest.Wait returns only once the ctx callback and
// deadline timer goroutines started in the bubble have returned or are durably blocked, whatever their code. A bubble
// that ends with a goroutine still blocked in it fails t without ending the test binary.
func inImageBubble(body func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		defer func() { r := recover(); require(t, r == nil, "synctest bubble: %v", r) }()
		synctest.Test(t, body)
	}
}

// cancelOnRead makes the next read call cancel before it returns, leaving the clock.
func (c *imageTestClock) cancelOnRead(cancel func()) { c.jumpOnRead(time.Time{}, cancel) }

// jumpOnRead makes the next read move the clock to now, or leave it when now is zero, and call cancel before it returns.
func (c *imageTestClock) jumpOnRead(now time.Time, cancel func()) {
	c.onNextRead(func(at time.Time) time.Time {
		cancel()
		return cmp.Or(now, at)
	})
}

// onReadFrom makes the first later read made inside a function whose name ends with suffix move the clock to what
// at returns; the reads until then leave the clock unchanged.
func (c *imageTestClock) onReadFrom(suffix string, at func(time.Time) time.Time) {
	var hook func(time.Time) time.Time
	hook = func(now time.Time) time.Time {
		if imageCalledFrom(suffix) {
			return at(now)
		}
		c.onRead = hook
		return now
	}
	c.onNextRead(hook)
}

// readFrom returns a channel closed by the first later clock read made inside a function whose name ends with
// suffix; the reads until then leave the clock unchanged.
func (c *imageTestClock) readFrom(suffix string) <-chan struct{} {
	read := make(chan struct{})
	c.onReadFrom(suffix, func(now time.Time) time.Time { close(read); return now })
	return read
}

// imageWire is the write side of one session connection: a write is recorded and succeeds; an armed
// stall blocks the write after its skipped writes until it receives a result (an error fails the
// write unrecorded) or the connection closes; an armed panic panics in the next write before it
// records a byte. A write after the close fails with net.ErrClosed unrecorded.
type imageWire struct {
	mu        sync.Mutex
	sent      []byte
	stall     *imageStall
	stallSkip int
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
	w.panicNext = nil
	if w.stallSkip > 0 {
		w.stallSkip, stall = w.stallSkip-1, nil
	} else {
		w.stall = nil
	}
	w.mu.Unlock()
	if value != nil {
		panic(value)
	}
	if stall != nil {
		close(stall.entered)
		select {
		case err := <-stall.release:
			if err != nil {
				return 0, err
			}
		case <-w.closed:
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

func (w *imageWire) armStall() *imageStall { return w.armStallAfter(0) }

// armStallAfter arms a stall for the write that follows skip more successful writes.
func (w *imageWire) armStallAfter(skip int) *imageStall {
	stall := &imageStall{entered: make(chan struct{}), release: make(chan error, 1)}
	w.mu.Lock()
	w.stall, w.stallSkip = stall, skip
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

// newImageTestFixtureAt starts the controlled clock at start, which also fixes its clock domain. Its cleanup closes the
// Service, which closes the session connections, ending a stalled write, and waits for the calls that hold a lease.
func newImageTestFixtureAt(t *testing.T, sessions int, start time.Time) *imageTestFixture {
	t.Helper()
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	f := &imageTestFixture{t: t, h: h, s: h.service, clock: &imageTestClock{t: t, now: start}}
	t.Cleanup(func() { requireReturned(t, lifecycleClose(f.s), "Close at cleanup") })
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

// imageTestLimits has large count and byte limits, Backoff 1 s and the given AttemptLifetime and
// RoundLifetime, 10 s and 1 hour when not given.
func imageTestLimits(lifetimes ...time.Duration) ImageLimits {
	d := [2]time.Duration{10 * time.Second, time.Hour}
	copy(d[:], lifetimes)
	return ImageLimits{
		PerPeer: imageTestUnits(1 << 20), Global: imageTestUnits(1 << 20),
		AttemptLifetime: d[0], RoundLifetime: d[1], Backoff: time.Second,
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

// begin calls BeginImageRound and fails the test when it has not returned within lifecycleWatchdog.
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

// callWithin runs call in its own goroutine, returns its result and fails the test when it has not returned within lifecycleWatchdog.
func callWithin[T any](t *testing.T, label string, call func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- call() }()
	return awaitImageResult(t, done, label)
}

var errImageNoResult = errors.New("request did not return within its bound")

var errImageScriptedWrite = errors.New("scripted write failure")

// launch starts the request in its own goroutine and delivers its result.
func launch(round *ImageRound, ctx context.Context, sourceID string, start byte, byteLimit uint32) <-chan imageResult {
	done := make(chan imageResult, 1)
	go func() {
		q, err := round.Request(ctx, sourceID, imageStart(start), byteLimit)
		done <- imageResult{q, err}
	}()
	return done
}

// requestWithin returns the request's result, or errImageNoResult when it has not returned within bound.
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

// awaitImageResult returns what done delivers, failing the test when it delivers nothing within lifecycleWatchdog.
func awaitImageResult[T any](t *testing.T, done <-chan T, label string) T {
	t.Helper()
	result, ok := receiveWithin(done, lifecycleWatchdog)
	require(t, ok, "%s did not return within %s", label, lifecycleWatchdog)
	return result
}

// requireQueryResult checks that got carries the query want and that its error is wantErr itself, not a value that wraps or matches it.
func requireQueryResult(t *testing.T, got imageResult, want consensus.UTXOImageQuery, wantErr error, label string) {
	t.Helper()
	ok := got.q == want && got.err == wantErr //nolint:errorlint // The returned error is wantErr itself, not a value that wraps it.
	require(t, ok, "%s: q=%+v err=%v, want q=%+v err=%v", label, got.q, got.err, want, wantErr)
}

// requireImageResult checks the query with wantID and start at the test anchor and byte limit and that the error is wantErr itself.
func requireImageResult(t *testing.T, got imageResult, wantID uint64, start byte, wantErr error, label string) {
	t.Helper()
	requireQueryResult(t, got, expectedImageQuery(wantID, start), wantErr, label)
}

// admitted checks that the request is admitted with wantID and returns the current instance of start read after it returned.
func (f *imageTestFixture) admitted(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte, wantID uint64) *imageInstance {
	t.Helper()
	requireImageResult(t, f.request(round, ctx, session, start), wantID, start, nil, fmt.Sprintf("request session %d start %d", session, start))
	return f.instance(start)
}

// failedOnClosed requests start, new to round, on session after its connection was closed and checks the admitted
// query with wantID and net.ErrClosed, no frame, one more Close, that last error, a zero ban score, and one ID,
// distinct start, source attempt, admitted request, attempted mark and start mark more with nothing else held.
func (f *imageTestFixture) failedOnClosed(t *testing.T, round *ImageRound, session int, start byte, wantID uint64) {
	t.Helper()
	want := f.snapshot(round, session)
	requireImageResult(t, f.request(round, context.Background(), session, start), wantID, start, net.ErrClosed, "request on the closed connection")
	charge := imageUsage(0, 1, 1, 1, 0)
	want.perPeer.add(charge)
	want.global.add(charge)
	want.ids, want.attempted, want.starts, want.closes, want.lastError, want.banScore = want.ids+1, want.attempted+1, want.starts+1, want.closes+1, net.ErrClosed.Error(), 0
	after := f.snapshot(round, session)
	require(t, after == want, "request on the closed connection: state %+v, want %+v", after, want)
}

// imageOwners is the requester state, and for a round its state, that a refusal leaves unchanged apart from what its
// pass releases: the wrapping sum of the sessions' last request IDs, the registry size, the round's usage on one
// session and in total, and the counts of its attempted and admitted-start marks.
type imageOwners struct {
	ids               uint64
	current           int
	perPeer, global   imageUnitVector
	attempted, starts int
}

// imageSnapshot is the owner state with one session's written bytes, Close count, last error and ban score.
type imageSnapshot struct {
	imageOwners
	wire, closes int
	lastError    string
	banScore     int
}

// imageOneInstance is the owner state of a single-source round, read on that source, after one admission whose
// frame was written or failed, with current 1 while that instance is current and 0 once it is retired.
func imageOneInstance(current int) imageOwners {
	usage := imageUsage(uint64(current), 1, 1, 1, 0)
	return imageOwners{ids: 1, current: current, perPeer: usage, global: usage, attempted: 1, starts: 1}
}

// lockRequester takes the requester mutex, failing the test when it is not free within lifecycleWatchdog.
func (f *imageTestFixture) lockRequester() *imageRequester {
	f.t.Helper()
	req := f.s.imageRequester
	waitUntil(f.t, req.mu.TryLock, "requester mutex")
	return req
}

// peerFault returns session's last error and ban score, failing the test when its state mutex is not free within lifecycleWatchdog.
func (f *imageTestFixture) peerFault(session int) (string, int) {
	f.t.Helper()
	p := f.peers[session]
	waitUntil(f.t, p.stateMu.TryLock, "peer state mutex")
	defer p.stateMu.Unlock()
	return p.state.LastError, p.state.BanScore
}

// requireFault checks that session's connection was closed closes times, that its last error is lastError and that
// its ban score is 0.
func (f *imageTestFixture) requireFault(t *testing.T, session, closes int, lastError, label string) {
	t.Helper()
	got, banScore := f.peerFault(session)
	require(t, f.closes(session) == closes && got == lastError && banScore == 0, "%s: closes=%d last error %q ban score %d, want %d, %q and 0", label, f.closes(session), got, banScore, closes, lastError)
}

// owners reads the owner state under the requester mutex, its round part only when round is not nil.
func (f *imageTestFixture) owners(round *ImageRound, session int) imageOwners {
	req := f.lockRequester()
	defer req.mu.Unlock()
	owners := imageOwners{current: len(req.current)}
	for _, id := range req.lastID {
		owners.ids += id
	}
	if round != nil {
		owners.perPeer, owners.global, owners.attempted, owners.starts = *round.usageFor(f.peers[session]), round.global, len(round.attempted), len(round.starts)
	}
	return owners
}

func (f *imageTestFixture) requireOwners(t *testing.T, round *ImageRound, session int, want imageOwners, label string) {
	t.Helper()
	got := f.owners(round, session)
	require(t, got == want, "%s: owner state %+v, want %+v", label, got, want)
}

func (f *imageTestFixture) snapshot(round *ImageRound, session int) imageSnapshot {
	snap := imageSnapshot{imageOwners: f.owners(round, session), wire: len(f.wires[session].bytes()), closes: f.closes(session)}
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

// refusedAfterPass requests start on session and checks the refusal want, whose pass releases exactly drop and changes nothing else.
func (f *imageTestFixture) refusedAfterPass(t *testing.T, round *ImageRound, session int, start byte, want error, drop imageDrop) {
	t.Helper()
	f.refusedDropping(t, round, context.Background(), f.ids[session], session, start, imageTestByteLimit, want, drop)
}

func (f *imageTestFixture) refusedDropping(t *testing.T, round *ImageRound, ctx context.Context, sourceID string, session int, start byte, byteLimit uint32, want error, drop imageDrop) {
	t.Helper()
	wantAfter := f.snapshot(round, session)
	got := requestWithin(lifecycleWatchdog, round, ctx, sourceID, start, byteLimit)
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, want, fmt.Sprintf("start %d", start))
	wantAfter.current -= drop.current
	wantAfter.perPeer[unitCurrentAssignments] -= drop.perPeer
	wantAfter.global[unitCurrentAssignments] -= drop.global
	after := f.snapshot(round, session)
	require(t, after == wantAfter, "start %d: state after the refusal %+v, want %+v", start, after, wantAfter)
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

// imageUsage is the usage vector with the given current assignments, distinct starts, source
// attempts, admitted requests and pending request bytes and zero in the other units.
func imageUsage(current, starts, attempts, admitted, pending uint64) imageUnitVector {
	return ImageUnits{CurrentAssignments: current, DistinctStarts: starts, SourceAttempts: attempts, AdmittedRequests: admitted, PendingNetworkBytes: pending}.vector()
}

// requireUsage compares round's whole usage vector on session with perPeer and its whole global usage vector with global.
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

// waitRetired runs in a bubble: after synctest.Wait it checks that inst is retired and returns its recorded end.
func (f *imageTestFixture) waitRetired(t *testing.T, inst *imageInstance, label string) error {
	t.Helper()
	synctest.Wait()
	retired, end := f.ended(inst)
	require(t, retired, "%s: instance not retired", label)
	return end
}

func (f *imageTestFixture) waitAdmitted(t *testing.T, session int, id uint64, label string) {
	t.Helper()
	waitUntil(t, func() bool { return f.lastID(session) == id }, fmt.Sprintf("%s: allocation of id %d", label, id))
}

// imageRequestCommand is the 12-byte command field 6765747574786f696d670000 of the request frame (RUBIN_L1_P2P_AUX.md Section 7.1).
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

// isImageRequestCommand reports whether command, NUL-padded to 12 bytes as readFrame checked it, is imageRequestCommand.
func isImageRequestCommand(command string) bool {
	if len(command) > len(imageRequestCommand) {
		return false
	}
	var field [12]byte
	copy(field[:], command)
	return field == imageRequestCommand
}

// requireFrames compares the decoded getutxoimg queries written on session with want, field by field and in order.
func (f *imageTestFixture) requireFrames(t *testing.T, session int, label string, want ...consensus.UTXOImageQuery) {
	t.Helper()
	got := f.frames(t, session)
	require(t, slices.Equal(got, want), "%s: session %d getutxoimg queries=%+v, want %+v", label, session, got, want)
}

func (f *imageTestFixture) closes(session int) int {
	_, closes := f.conns[session].snapshot()
	return closes
}

// holdWrite stalls a ping frame write on session, which keeps its writeMu until release lets it
// finish; release returns that write's error within lifecycleWatchdog.
func (f *imageTestFixture) holdWrite(t *testing.T, session int) (release func() error) {
	t.Helper()
	stall := f.wires[session].armStall()
	done := make(chan error, 1)
	go func() { done <- f.peers[session].send(messagePing, make([]byte, 8)) }()
	requireChannelClosed(t, stall.entered, "holder write")
	return func() error {
		t.Helper()
		stall.release <- nil
		return awaitImageResult(t, done, "holder write")
	}
}

// stalledRequest starts the request for start on session with its frame write stalled and returns once that write has started.
func (f *imageTestFixture) stalledRequest(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte) (*imageStall, <-chan imageResult) {
	t.Helper()
	stall := f.wires[session].armStall()
	pending := f.goRequest(round, ctx, session, start)
	requireChannelClosed(t, stall.entered, fmt.Sprintf("stalled write of start %d on session %d", start, session))
	return stall, pending
}

func TestImageRequesterRound(t *testing.T) {
	t.Run("ids start at one and increase across rounds, expiry, cancellation and a failed write", inImageBubble(testImageIDsIncrease))
	t.Run("the maximum id is issued once and later requests on that session refuse without wrap", testImageIDMaximum)
	t.Run("one current assignment per anchor and start across the service", inImageBubble(testImageOneCurrent))
	t.Run("one of concurrent requests for one anchor and start is admitted", testImageOneCurrentRace)
	t.Run("count limits pass at equality and refuse one over before an id", testImageCountLimits)
	t.Run("pending request bytes pass at equality and refuse one over", testImagePendingBytes)
	t.Run("distinct starts count the round's admitted starts", inImageBubble(testImageDistinctStarts))
	t.Run("usage and release are per round", testImagePerRoundUsage)
	t.Run("attempt and round deadlines and no renewal", inImageBubble(testImageDeadlines))
	t.Run("pre-write decision at D and one tick after", testImagePreWriteAtDeadline)
	t.Run("an end while waiting for writeMu stops the write", testImageEndBeforeWrite)
	t.Run("a request past the checks that need no registry state retires the ended instances of the service before its round deadline check", testImageRequestRetiresEnded)
	t.Run("an end during the running write", testImageEndDuringWrite)
	t.Run("the frame write deadline is the frame budget, not D, RD or a ctx deadline", testImageFrameWriteDeadline)
	t.Run("ctx callbacks and the deadline timer with no further request", testImageCallbacksAndTimer)
	t.Run("a failed write keeps the query, the id and the work and retires only that assignment", testImageFailedWrite)
	t.Run("a stale handle leaves its replacement current", testImageStaleHandle)
	t.Run("round refusals in order", testImageRoundRefusals)
	t.Run("more source ids than service entries refuse with less allocation than the source list", testImageSourceBound)
	t.Run("the source decision after the Service.peers copy refuses one more id than entries, an id with no entry and an alias pair, and resolves only the listed ids", testImageSourceDecision)
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
	inst := f.admitted(t, second, ctx, 0, 2, 3)
	cancel()
	f.waitRetired(t, inst, "canceled instance")
	f.admitted(t, second, context.Background(), 1, 2, 1)
	f.admitted(t, second, context.Background(), 0, 3, 4)
	f.wires[0].armStall().release <- errImageScriptedWrite
	requireImageResult(t, f.request(second, context.Background(), 0, 4), 5, 4, errImageScriptedWrite, "failed write")
	f.requireFault(t, 0, 1, errImageScriptedWrite.Error(), "after the failed write")
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
	limits := imageTestLimits(50 * time.Millisecond)
	first := f.round(t, limits, 0, 1, 2)
	second := f.round(t, limits, 0, 1, 2)
	reads := f.clock.readCount()
	stall, pending := f.stalledRequest(t, first, context.Background(), 0, 1)
	f.requireTimerSpent(t, imageTestAnchor, 1, reads+3)
	f.refused(t, second, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.admitTimerSpent(t, second, context.Background(), 1, 2, 1)
	stall.release <- nil
	requireImageResult(t, awaitImageResult(t, pending, "stalled request"), 1, 1, nil, "stalled request")
	f.requireFrames(t, 1, "parallel start", expectedImageQuery(1, 2))
	var wantOther []consensus.UTXOImageQuery
	for i, change := range []func(*ImageAnchor){
		func(a *ImageAnchor) { a.Height = 8 }, func(a *ImageAnchor) { a.BlockHash[0] = 0xb2 }, func(a *ImageAnchor) { a.Root[0] = 0x53 },
	} {
		other := imageTestAnchor
		change(&other)
		otherRound, err := f.begin(context.Background(), ImageRoundConfig{Anchor: other, SourceIDs: []string{f.ids[2]}, Limits: limits})
		must(t, err, "BeginImageRound other anchor")
		want := expectedImageQuery(uint64(i+1), 1)
		want.Height, want.BlockHash, want.Root = other.Height, other.BlockHash, other.Root
		reads = f.clock.readCount()
		requireQueryResult(t, f.request(otherRound, context.Background(), 2, 1), want, nil, fmt.Sprintf("anchor %d with the same start", i))
		f.requireTimerSpent(t, other, 1, reads+3)
		wantOther = append(wantOther, want)
	}
	f.requireFrames(t, 2, "other anchors with the same start", wantOther...)
	f.clock.add(50*time.Millisecond + time.Nanosecond)
	f.refusedAfterPass(t, first, 0, 1, errImageAttempted, imageDrop{1, 1, 5})
	f.admitted(t, first, context.Background(), 1, 1, 2)
}

// testImageOneCurrentRace releases requests for one anchor and start on eight sessions together:
// exactly one is admitted and writes its frame, and the others refuse with errImageAssignmentCurrent.
func testImageOneCurrentRace(t *testing.T) {
	f := newImageTestFixture(t, 8)
	round := f.round(t, imageTestLimits(), 0, 1, 2, 3, 4, 5, 6, 7)
	gate, results := make(chan struct{}), make([]chan imageResult, len(f.ids))
	for i := range results {
		results[i] = make(chan imageResult, 1)
		go func() {
			<-gate
			results[i] <- <-launch(round, context.Background(), f.ids[i], 1, imageTestByteLimit)
		}()
	}
	close(gate)
	var admitted []int
	for i, done := range results {
		if got := awaitImageResult(t, done, "concurrent request"); got.err != nil {
			requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageAssignmentCurrent, fmt.Sprintf("concurrent request on session %d", i))
			f.requireFrames(t, i, "refused concurrent request")
		} else {
			admitted = append(admitted, i)
			requireImageResult(t, got, 1, 1, nil, "admitted concurrent request")
			f.requireFrames(t, i, "admitted concurrent request", expectedImageQuery(1, 1))
		}
	}
	requireEqual(t, len(admitted), 1, "admitted concurrent requests")
	f.requireOwners(t, round, admitted[0], imageOneInstance(1), "after the concurrent requests")
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
			t.Run(fmt.Sprintf("%s global=%v", tc.name, global), inImageBubble(func(t *testing.T) {
				f := newImageTestFixture(t, 2)
				limits := imageTestLimits()
				scope := map[bool]*ImageUnits{false: &limits.PerPeer, true: &limits.Global}[global]
				*tc.field(scope) = 2
				round := f.round(t, limits, 0, 1)
				ctx, cancel := context.WithCancel(context.Background())
				inst := f.admitted(t, round, ctx, 0, 1, 1)
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
			}))
		}
	}
}

// testImagePendingBytes holds 120 request bytes on session 0 in a stalled write: a global or per-peer
// pending-byte limit of 240 admits start 2, on session 1 or 0, and 239 refuses it.
func testImagePendingBytes(t *testing.T) {
	for _, tc := range []struct {
		global  bool
		limit   uint64
		session int
	}{{true, 240, 1}, {true, 239, 1}, {false, 240, 0}, {false, 239, 0}} {
		t.Run(fmt.Sprintf("global=%v limit %d", tc.global, tc.limit), func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			limits := imageTestLimits()
			scope := map[bool]*ImageUnits{false: &limits.PerPeer, true: &limits.Global}[tc.global]
			scope.PendingNetworkBytes = tc.limit
			round := f.round(t, limits, 0, 1)
			stall, held := f.stalledRequest(t, round, context.Background(), 0, 1)
			var next <-chan imageResult
			if tc.limit == 239 {
				f.refused(t, round, context.Background(), tc.session, 2, errImageLimit)
			} else {
				next = f.goRequest(round, context.Background(), tc.session, 2)
				f.waitAdmitted(t, tc.session, uint64(2-tc.session), "request at the limit")
			}
			stall.release <- nil
			requireImageResult(t, awaitImageResult(t, held, "held request"), 1, 1, nil, "held request")
			if next != nil {
				requireImageResult(t, awaitImageResult(t, next, "request at the limit"), uint64(2-tc.session), 2, nil, "request at the limit")
			}
		})
	}
}

func testImageDistinctStarts(t *testing.T) {
	f := newImageTestFixture(t, 2)
	limits := imageTestLimits()
	limits.Global.DistinctStarts, limits.AttemptLifetime = 1, 50*time.Millisecond
	round := f.round(t, limits, 0, 1)
	f.admitTimerSpent(t, round, context.Background(), 0, 1, 1)
	f.clock.add(50*time.Millisecond + time.Nanosecond)
	f.admitTimerSpent(t, round, context.Background(), 1, 1, 1)
	f.requireUsage(t, round, 1, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "the start admitted again on the second session")
	f.clock.add(50*time.Millisecond + time.Nanosecond)
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
		stall, first := f.stalledRequest(t, r1, context.Background(), 0, 1)
		second := f.goRequest(r2, context.Background(), 0, 2)
		f.waitAdmitted(t, 0, 2, "second round admission")
		f.refused(t, r1, context.Background(), 0, 2, errImageAssignmentCurrent)
		stall.release <- nil
		requireImageResult(t, awaitImageResult(t, first, "first round"), 1, 1, nil, "first round")
		requireImageResult(t, awaitImageResult(t, second, "second round"), 2, 2, nil, "second round")
		f.requireFrames(t, 0, "both rounds", expectedImageQuery(1, 1), expectedImageQuery(2, 2))
	})
	t.Run("a retirement releases its own round", inImageBubble(func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		limits := imageTestLimits(time.Second + 50*time.Millisecond)
		limits.PerPeer.CurrentAssignments, limits.Global.CurrentAssignments = 1, 1
		r1, r2 := f.round(t, limits, 0), f.round(t, limits, 0)
		ended := f.admitTimerSpent(t, r1, context.Background(), 0, 1, 1)
		f.clock.add(time.Second)
		f.admitted(t, r2, context.Background(), 0, 2, 2)
		f.clock.set(ended.deadline.Add(time.Nanosecond))
		f.refusedAfterPass(t, r2, 0, 3, errImageLimit, imageDrop{0, 0, 1})
		f.admitted(t, r1, context.Background(), 0, 4, 3)
	}))
	t.Run("a value copy of a round is that round", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		limits := imageTestLimits()
		limits.Global.AdmittedRequests = 1
		round := f.round(t, limits, 0, 1)
		copied := *round
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.refused(t, &copied, context.Background(), 1, 2, errImageLimit)
	})
	t.Run("a request and its instance keep the round the caller's round variable held at the call", inImageBubble(func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		r1, limits := f.round(t, imageTestLimits(), 0, 1), imageTestLimits(20*time.Second)
		limits.PerPeer.CurrentAssignments = 1
		r2, err := f.begin(context.Background(), ImageRoundConfig{Anchor: ImageAnchor{Height: 8, BlockHash: imageTestAnchor.BlockHash, Root: imageTestAnchor.Root}, SourceIDs: f.ids[:1], Limits: limits})
		must(t, err, "BeginImageRound other anchor")
		variable := *r1
		ctx, cancel := context.WithCancel(context.Background())
		inst := f.admitted(t, &variable, ctx, 0, 1, 1)
		requireQueryResult(t, f.request(r2, context.Background(), 0, 2), consensus.UTXOImageQuery{RequestID: 2, Height: 8, BlockHash: imageTestAnchor.BlockHash, Root: imageTestAnchor.Root, StartKey: imageStart(2), ByteLimit: imageTestByteLimit}, nil, "other round")
		variable = *r2
		cancel()
		end := f.waitRetired(t, inst, "canceled instance")
		f.admitted(t, r1, context.Background(), 1, 1, 1)
		f.refused(t, r2, context.Background(), 0, 3, errImageLimit)
		called := *r1
		f.clock.onNextRead(func(now time.Time) time.Time { called = *r2; return now })
		reassigned := f.admitted(t, &called, context.Background(), 1, 4, 2)
		require(t, reassigned != nil && reassigned.round.imageRoundUsage == r1.imageRoundUsage && reassigned.deadline.Equal(f.clock.add(0).Add(10*time.Second)), "instance of the request whose round variable was reassigned at its admission clock read: not in the called round with D 10 s after now")
		f.requireFrames(t, 1, "admitting round", expectedImageQuery(1, 1), expectedImageQuery(2, 4))
		require(t, end == context.Canceled && f.instance(1) != inst, "canceled instance end=%v, still registered=%v", end, f.instance(1) == inst) //nolint:errorlint // The recorded end is the ctx's Err() itself.
		f.requireUsage(t, r1, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(2, 2, 3, 3, 0), "admitting round")
		f.requireUsage(t, r1, 1, imageUsage(2, 2, 2, 2, 0), imageUsage(2, 2, 3, 3, 0), "called round on session 1")
		f.requireUsage(t, &variable, 0, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 1, 1, 0), "round the variable holds")
	}))
}

func testImageDeadlines(t *testing.T) {
	f := newImageTestFixture(t, 5)
	t0, limits := f.clock.Now(), imageTestLimits(10*time.Second, 60*time.Second)
	round := f.round(t, limits, 0, 1, 2, 3, 4)
	first := f.admitted(t, round, context.Background(), 0, 1, 1)
	require(t, first.deadline.Equal(t0.Add(10*time.Second)), "D=%v", first.deadline)
	f.clock.set(t0.Add(10 * time.Second))
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
	f.admitted(t, round, context.Background(), 1, 1, 1)
	require(t, f.instance(1).deadline.Equal(t0.Add(20*time.Second+time.Nanosecond)) && first.deadline.Equal(t0.Add(10*time.Second)), "reassigned D=%v first D=%v", f.instance(1).deadline, first.deadline)
	f.wires[4].armStall().release <- errImageScriptedWrite
	requireImageResult(t, f.request(round, context.Background(), 4, 5), 1, 5, errImageScriptedWrite, "failed write")
	f.requireFault(t, 4, 1, errImageScriptedWrite.Error(), "after the failed write")
	f.requireUsage(t, round, 4, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 2, 3, 3, 0), "after the failed write")
	ctx, cancel := context.WithCancel(context.Background())
	ended := f.admitted(t, round, ctx, 3, 6, 1)
	cancel()
	f.waitRetired(t, ended, "canceled instance")
	f.clock.set(t0.Add(60*time.Second - 50*time.Millisecond))
	reads := f.clock.readCount()
	capped := f.admitted(t, round, context.Background(), 2, 2, 1)
	require(t, capped.deadline.Equal(t0.Add(60*time.Second)), "D capped by RD: %v", capped.deadline)
	f.requireTimerSpent(t, imageTestAnchor, 2, reads+3)
	f.clock.set(t0.Add(60*time.Second - time.Nanosecond))
	f.admitTimerSpent(t, round, context.Background(), 2, 3, 2)
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
		past time.Duration
	}{{"now at D writes the frame", 0}, {"now one tick past D writes no frame", time.Nanosecond}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			t0 := f.clock.Now()
			round := f.round(t, imageTestLimits(), 0)
			release := f.holdWrite(t, 0)
			pending := f.goRequest(round, context.Background(), 0, 1)
			f.waitAdmitted(t, 0, 1, "parked request")
			f.clock.set(t0.Add(10*time.Second + tc.past))
			if tc.past > 0 {
				requireImageResult(t, awaitImageResult(t, pending, "one tick past D"), 1, 1, errImageExpired, "one tick past D")
			}
			must(t, release(), "holder write")
			if tc.past > 0 {
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

// imageEndCase ends a request parked on writeMu. With callback set, the end cancels a ctx inside the parked request's
// own clock read, after the 50 ms deadline timer read the clock short of D: its callback runs after that retirement.
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
			want: errImageExpired, notWant: []error{errImageNilContext, errImagePolicy, errImageSourceSet, errImageUnknownSource, errImageRoundDeadline, errImageAssignmentCurrent, errImageAttempted, errImageLimit, errImageIDExhausted, errImageRequestDomain, errServiceClosed, context.Canceled, context.DeadlineExceeded, os.ErrDeadlineExceeded},
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
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0, limits := f.clock.Now(), imageTestLimits(cmp.Or(tc.lifetime, 10*time.Second))
			roundCtx, cancelRound := context.WithCancel(context.Background())
			defer cancelRound()
			round := f.roundCtx(t, roundCtx, limits, 0, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			release := f.holdWrite(t, 0)
			var timerRead <-chan struct{}
			if tc.callback {
				timerRead = f.clock.readFrom(".(*Service).applyImageEnd")
			}
			pending := f.goRequest(round, ctx, 0, 1)
			f.waitAdmitted(t, 0, 1, "parked request")
			if tc.callback {
				requireChannelClosed(t, timerRead, "deadline timer read")
				synctest.Wait()
			}
			tc.apply(f, t0, cancel, cancelRound)
			got := awaitImageResult(t, pending, "parked request")
			requireImageResult(t, got, 1, 1, tc.want, "while another write holds writeMu")
			for _, other := range tc.notWant {
				require(t, !errors.Is(got.err, other), "end error %v matches %v", got.err, other)
			}
			require(t, !errors.Is(tc.want, errImageExpired) || got.err.Error() == "image requester: attempt expired" && errors.Unwrap(got.err) == nil, "expiry error %q wraps %v, want the text image requester: attempt expired wrapping nothing", got.err, errors.Unwrap(got.err))
			requireEqual(t, f.closes(0), 0, "session closes after the end")
			synctest.Wait()
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
		}))
	}
	t.Run("frozen now keeps the wait parked for 200 ms of wall time until the ctx ends", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		limits := imageTestLimits(50 * time.Millisecond)
		round := f.round(t, limits, 0)
		ctx, cancel := context.WithCancel(context.Background())
		release := f.holdWrite(t, 0)
		// No ctx is done before the cancel, so the first clock read inside applyImageEnd is the deadline timer's; the
		// cancel runs inside a clock read of the parked request's endBeforeWrite, which holds the requester mutex.
		timerRead := f.clock.readFrom(".(*Service).applyImageEnd")
		pending := f.goRequest(round, ctx, 0, 1)
		f.waitAdmitted(t, 0, 1, "parked request")
		_, returned := receiveWithin(pending, 200*time.Millisecond)
		require(t, !returned, "frozen now: the parked request returned")
		requireChannelClosed(t, timerRead, "deadline timer read")
		f.clock.onReadFrom(".(*ImageRound).endBeforeWrite", func(now time.Time) time.Time { cancel(); return now })
		got := awaitImageResult(t, pending, "canceled wait")
		requireImageResult(t, got, 1, 1, context.Canceled, "canceled wait")
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

// imageCalledFrom reports whether the calling goroutine's stack holds a function whose name ends with suffix.
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

// testImageRecordedEndKept parks a request on writeMu; another session's pass retires it with
// errImageExpired, then a pre-write clock read cancels one of its ctxs: it returns the recorded end,
// releases its request bytes once and writes no frame.
func testImageRecordedEndKept(t *testing.T) {
	for _, tc := range []struct {
		name  string
		round bool
	}{{"request ctx", false}, {"round ctx", true}} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0 := f.clock.Now()
			roundCtx, cancelRound := context.WithCancel(context.Background())
			defer cancelRound()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			end := map[bool]func(){false: cancel, true: cancelRound}[tc.round]
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
			synctest.Wait()
			_, recorded := f.ended(inst)
			require(t, recorded == errImageExpired, "recorded end=%v", recorded) //nolint:errorlint // The recorded end is errImageExpired itself.
			f.requireUsage(t, parked, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "after the recorded end")
			must(t, release(), "holder write")
			f.requireFrames(t, 0, "after the recorded end")
		}))
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

// testImageDoneAtAdmissionRead ends one ctx, or both, of a request for start 1 on session 1, and moves now
// past the D of the current instance of start 1, at the request's admission clock read. It refuses with
// that ctx's error, the request ctx's when both end, writes no frame and retires nothing; the next live request, on a new round when
// the round ctx ended, is admitted with ID 1 and its pass records errImageExpired.
func testImageDoneAtAdmissionRead(t *testing.T) {
	requestEnd, roundEnd := errors.New("request ctx ended"), errors.New("round ctx ended")
	endCtx := func() (context.Context, context.CancelFunc) { return newImageEndCtx(requestEnd) }
	cancelCtx := func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }
	for _, tc := range []struct {
		name, ends string
		requestCtx func() (context.Context, context.CancelFunc)
		want       error
	}{
		{"request ctx", "request", endCtx, requestEnd},
		{"request ctx from context.WithCancel", "request", cancelCtx, context.Canceled},
		{"round ctx", "round", endCtx, roundEnd},
		{"request ctx and round ctx", "both", endCtx, requestEnd},
	} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			roundCtx, cancelRound := newImageEndCtx(roundEnd)
			defer cancelRound()
			ctx, cancel := tc.requestCtx()
			defer cancel()
			end := map[string]func(){"request": cancel, "round": cancelRound, "both": func() { cancel(); cancelRound() }}[tc.ends]
			limits := imageTestLimits(50 * time.Millisecond)
			round := f.roundCtx(t, roundCtx, limits, 0, 1)
			firstRound := round
			if tc.ends != "request" {
				firstRound = f.round(t, limits, 0, 1)
			}
			first := f.admitTimerSpent(t, firstRound, context.Background(), 0, 1, 1)
			hooked := false
			f.clock.onReadFrom(".(*ImageRound).admit", func(time.Time) time.Time {
				hooked = true
				end()
				return first.deadline.Add(time.Nanosecond)
			})
			f.refused(t, round, ctx, 1, 1, tc.want)
			require(t, hooked, "the admission clock read did not run the hook")
			retired, recorded := f.ended(first)
			require(t, !retired && recorded == nil, "first instance after the refusal: retired=%v end=%v, want current", retired, recorded)
			f.requireUsage(t, firstRound, 0, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 1, 1, 0), "first instance's round after the refusal")
			next := round
			if tc.ends != "request" {
				next = f.round(t, imageTestLimits(), 0, 1)
			}
			f.admitted(t, next, context.Background(), 1, 1, 1)
			_, recorded = f.ended(first)
			require(t, recorded == errImageExpired, "first instance end after the next request=%v, want %v", recorded, errImageExpired) //nolint:errorlint // The recorded end is errImageExpired itself.
		}))
	}
}

func testImageRequestRetiresEnded(t *testing.T) {
	t.Run("same round", inImageBubble(func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		limits := imageTestLimits(50 * time.Millisecond)
		round := f.round(t, limits, 0, 1)
		ctx, cancel := context.WithCancel(context.Background())
		inst := f.admitTimerSpent(t, round, ctx, 0, 1, 1)
		f.clock.set(inst.deadline)
		f.refused(t, round, context.Background(), 0, 1, errImageAssignmentCurrent)
		f.clock.set(inst.deadline.Add(time.Nanosecond))
		f.refusedAfterPass(t, round, 0, 1, errImageAttempted, imageDrop{1, 1, 1})
		retired, end := f.ended(inst)
		require(t, retired && end == errImageExpired, "pass: retired=%v end=%v", retired, end) //nolint:errorlint // The recorded end is errImageExpired itself.
		f.admitted(t, round, context.Background(), 0, 2, 2)
		f.admitted(t, round, context.Background(), 1, 1, 1)
		cancel()
		synctest.Wait()
		_, end = f.ended(inst)
		require(t, end == errImageExpired, "end after cancellation=%v", end) //nolint:errorlint // The recorded end is errImageExpired itself.
		f.refused(t, round, context.Background(), 0, 1, errImageAssignmentCurrent)
		replacement := f.instance(1)
		require(t, replacement != nil && replacement.session == f.peers[1], "replacement not current")
		f.admitted(t, round, context.Background(), 0, 3, 3)
		requireEqual(t, f.lastID(1), uint64(1), "replacement session last id")
	}))
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

// imageEndCtx is a cancellable context whose Err, once it is done, is err, so a recorded end names the context it came from.
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

// testImagePassEndOrder ends an instance at the admission clock read of another session's request
// for its start, whose pass retires it under the requester mutex ahead of its ctx callbacks.
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
			inst := f.admitted(t, ended, ctx, 0, 1, 1)
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
			want := before
			want[unitCurrentAssignments]--
			f.requireUsage(t, ended, 0, want, want, "pass usage of the single-source round")
			requireEqual(t, f.lastID(0), uint64(1), "session 0 last id")
		})
	}
}

// testImageEarlyRefusalRetiresNothing moves now 24 hours past an instance's D, short of its timer,
// and checks that the listed refusals ahead of the pass leave it unretired until a later pass.
func testImageEarlyRefusalRetiresNothing(t *testing.T) {
	f := newImageTestFixture(t, 2)
	t0, limits := f.clock.Now(), imageTestLimits(24*time.Hour, 48*time.Hour)
	round := f.round(t, limits, 0)
	doneRoundCtx, cancelDoneRound := context.WithCancel(context.Background())
	cancelDoneRound()
	doneRound := f.roundCtx(t, doneRoundCtx, limits, 0)
	inst := f.admitted(t, round, context.Background(), 0, 1, 1)
	canceled, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	var nilCtx context.Context
	f.clock.set(t0.Add(24*time.Hour + time.Nanosecond))
	for i, tc := range []struct {
		round     *ImageRound
		ctx       context.Context
		session   int
		byteLimit uint32
		want      error
	}{
		{round, nilCtx, 0, imageTestByteLimit, errImageNilContext},
		{round, canceled, 0, imageTestByteLimit, context.Canceled},
		{doneRound, context.Background(), 0, imageTestByteLimit, context.Canceled},
		{round, context.Background(), 1, imageTestByteLimit, errImageUnknownSource},
		{round, context.Background(), 0, 150904, errImageRequestDomain},
	} {
		f.refusedWith(t, tc.round, tc.ctx, f.ids[tc.session], tc.session, 2, tc.byteLimit, tc.want)
		retired, _ := f.ended(inst)
		require(t, !retired, "refusal %d before the pass retired the ended instance", i)
	}
	f.admitted(t, round, context.Background(), 0, 2, 2)
	_, end := f.ended(inst)
	require(t, end == errImageExpired, "pass end=%v", end) //nolint:errorlint // The recorded end is errImageExpired itself.
}

// testImageClosedRefusalRetiresNothing ends an instance after Close, with its callback and timer
// refused a lease; a request refused by the closed Service then retires nothing and reads no clock.
func testImageClosedRefusalRetiresNothing(t *testing.T) {
	runImageBubble(t, false, func(t *testing.T, b imageBubble) {
		requireReturned(t, lifecycleClose(b.f.s), "Close")
		b.endRequest()
		b.expire()
		retired, reads, now, owners, end := b.state()
		require(t, !retired && end == nil && b.inst.ctx.Err() != nil && now.After(b.inst.deadline) && owners == imageOneInstance(1), "before the request: retired=%v end=%v ctx err=%v now %v D %v owner state %+v, want the ended instance unretired", retired, end, b.inst.ctx.Err(), now, b.inst.deadline, owners)
		b.f.refused(t, b.round, context.Background(), 0, 2, errServiceClosed)
		retired, after, _, owners, end := b.state()
		require(t, !retired && end == nil && after == reads && owners == imageOneInstance(1) && b.f.instance(1) == b.inst, "after the refusal: retired=%v end=%v clock reads %d->%d owner state %+v, want the ended instance unretired and the clock unread", retired, end, reads, after, owners)
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
			limits := imageTestLimits(math.MaxInt64)
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

// testImageRefusalKeepsPass checks that a request refused after its pass keeps the pass's retirement
// of an expired instance, errImageExpired with only its current assignment released; the clock starts
// at a time read outside the bubble, which carries a monotonic reading.
func testImageRefusalKeepsPass(t *testing.T) {
	for _, tc := range imagePassRefusals() {
		start := time.Now()
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixtureAt(t, 2, start)
			t0, limits := f.clock.Now(), imageTestLimits(50*time.Millisecond)
			limits.PerPeer.SourceAttempts = 1
			ended := f.round(t, limits, 0, 1)
			inst := f.admitTimerSpent(t, ended, context.Background(), 0, 1, 1)
			perPeerBefore, globalBefore := f.usage(ended, 0)
			round, session, start := tc.prepare(t, f, ended, t0)
			f.refusedAfterPass(t, round, session, start, tc.want, tc.drop)
			retired, end := f.ended(inst)
			require(t, retired && end == errImageExpired, "after the refusal: retired=%v end=%v", retired, end) //nolint:errorlint // The recorded end is errImageExpired itself.
			perPeerBefore[unitCurrentAssignments]--
			globalBefore[unitCurrentAssignments]--
			f.requireUsage(t, ended, 0, perPeerBefore, globalBefore, "ended round usage")
			requireEqual(t, f.lastID(0), uint64(1), "session 0 last id")
		}))
	}
}

func testImageEndDuringWrite(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pass     bool
		writeErr error
	}{
		{"request ctx, write succeeds", false, nil},
		{"request ctx, write fails", false, errImageScriptedWrite},
		{"expiry by another session's pass, write succeeds", true, nil},
		{"expiry by another session's pass, write fails", true, errImageScriptedWrite},
	} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0, limits := f.clock.Now(), imageTestLimits()
			limits.PerPeer.PendingNetworkBytes = 120
			round := f.round(t, limits, 0, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stall, pending := f.stalledRequest(t, round, ctx, 0, 1)
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
			_, end = f.ended(inst)
			require(t, end == wantEnd, "recorded end after the write=%v", end) //nolint:errorlint // The recorded end is the ctx's Err() or errImageExpired itself.
			f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after the write")
			if tc.writeErr != nil {
				f.requireFault(t, 0, 1, tc.writeErr.Error(), "after the failed write")
				f.requireFrames(t, 0, "after the failed write")
				f.failedOnClosed(t, round, 0, 2, 2)
				return
			}
			f.requireFault(t, 0, 0, "", "after the write")
			f.requireFrames(t, 0, "after the write", expectedImageQuery(1, 1))
			f.admitted(t, round, context.Background(), 0, 2, 2)
		}))
	}
	t.Run("round ctx canceled during the write", inImageBubble(func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		roundCtx, cancelRound := context.WithCancel(context.Background())
		round := f.roundCtx(t, roundCtx, imageTestLimits(), 0)
		stall, pending := f.stalledRequest(t, round, context.Background(), 0, 1)
		inst := f.instance(1)
		cancelRound()
		end := f.waitRetired(t, inst, "round ctx end")
		require(t, end == context.Canceled, "recorded end=%v", end) //nolint:errorlint // The recorded end is the round ctx's Err() itself.
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 120), imageUsage(0, 1, 1, 1, 120), "during the write")
		stall.release <- nil
		requireImageResult(t, awaitImageResult(t, pending, "written request"), 1, 1, nil, "after the write")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "after the write")
		f.requireFrames(t, 0, "round ctx end", expectedImageQuery(1, 1))
	}))
}

// testImageFrameWriteDeadline checks that every recorded write deadline of the request frame lies
// within the 15 s frame budget of the wall reads around Request, after D, RD and the ctx deadlines.
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
			limits := imageTestLimits(time.Second, tc.roundLifetime)
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
	for _, name := range []string{"round ctx", "request ctx after the request returned"} {
		t.Run(name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			roundCtx, cancelRound := context.WithCancel(context.Background())
			ctx, cancel := context.WithCancel(context.Background())
			round := f.roundCtx(t, roundCtx, imageTestLimits(), 0)
			inst := f.admitted(t, round, ctx, 0, 1, 1)
			map[string]func(){"round ctx": cancelRound, "request ctx after the request returned": cancel}[name]()
			end := f.waitRetired(t, inst, name)
			require(t, end == context.Canceled, "%s: end=%v", name, end) //nolint:errorlint // The recorded end is the canceled ctx's Err() itself.
			f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), name)
			cancelRound()
			cancel()
		}))
	}
	t.Run("deadline timer with D set by the round deadline", inImageBubble(testImageDeadlineTimer))
	t.Run("deadline timer with D the largest duration after now", inImageBubble(testImageSaturatedTimer))
	t.Run("deadline timer fires 1 ns after D", testImageTimerTick)
	t.Run("a ctx callback or the deadline timer refused a lease after close changes nothing", testImageCallbackOrTimerAfterClose)
	t.Run("a ctx callback that took its lease before close keeps Close waiting until it returns", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		ctx, cancel := context.WithCancel(context.Background())
		inst := f.admitted(t, f.round(t, imageTestLimits(), 0), ctx, 0, 1, 1)
		entered, release := f.blockNextRead(func(now time.Time) time.Time { return now }, func() {})
		cancel()
		requireReturned(t, f.closeWhileReadHeld(t, entered, release), "Close")
		_, end := f.ended(inst)
		requireEqual(t, end, context.Canceled, "end recorded by the callback before Close returned")
	})
	t.Run("a ctx callback or the deadline timer triggered after retirement does not run", testImageRetirementStops)
	t.Run("deadline timer with now not after D and the round ctx done before its callback runs", inImageBubble(testImageTimerShortOfD))
}

// testImageTimerShortOfD: with the round ctx done but its callback not run, the deadline timer reads
// the clock once short of D and records nothing; the Request ctx callback then records its error.
func testImageTimerShortOfD(t *testing.T) {
	f := newImageTestFixture(t, 1)
	limits := imageTestLimits(100 * time.Millisecond)
	roundCtx := newImageHookCtx()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	round := f.roundCtx(t, roundCtx, limits, 0)
	inst := f.admitted(t, round, ctx, 0, 1, 1)
	roundCtx.end(errors.New("round ctx ended"))
	reads := f.clock.readCount()
	time.Sleep(time.Second)
	synctest.Wait()
	req := f.lockRequester()
	retired, end, rearmed := inst.retired, inst.end, inst.timer.Stop()
	req.mu.Unlock()
	requireEqual(t, f.clock.readCount(), reads+1, "clock reads by the deadline timer")
	require(t, !retired && end == nil && !rearmed, "deadline timer short of D with the round ctx done: retired=%v end=%v armed again=%v, want current", retired, end, rearmed)
	cancel()
	synctest.Wait()
	_, end = f.ended(inst)
	require(t, end == context.Canceled, "request ctx callback end=%v, want %v", end, context.Canceled) //nolint:errorlint // The recorded end is the Request ctx's Err() itself.
}

// imageHookCtx is a Context whose Done stays open and Err is nil until end. AfterFunc keeps f and
// returns a stop func that removes it; onAfterFunc and onStop replace the first AfterFunc and stop,
// and onSecondErr runs inside the second Err call before it returns.
type imageHookCtx struct {
	mu                               sync.Mutex
	done                             chan struct{}
	err                              error
	errCalls                         int
	funcs                            map[*func()]struct{}
	onAfterFunc, onStop, onSecondErr func()
}

func newImageHookCtx() *imageHookCtx {
	return &imageHookCtx{done: make(chan struct{}), funcs: make(map[*func()]struct{})}
}

func (c *imageHookCtx) Deadline() (time.Time, bool) { return time.Time{}, false }

func (c *imageHookCtx) Done() <-chan struct{} { return c.done }

func (c *imageHookCtx) Value(any) any { return nil }

func (c *imageHookCtx) Err() error {
	c.mu.Lock()
	c.errCalls++
	err, hold := c.err, c.errCalls == 2 && c.onSecondErr != nil
	c.mu.Unlock()
	if hold {
		c.onSecondErr()
	}
	return err
}

func (c *imageHookCtx) end(err error) {
	c.mu.Lock()
	c.err = err
	close(c.done)
	c.mu.Unlock()
}

func (c *imageHookCtx) AfterFunc(f func()) func() bool {
	c.mu.Lock()
	hook := c.onAfterFunc
	c.onAfterFunc = nil
	if hook == nil {
		c.funcs[&f] = struct{}{}
	}
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	return func() bool { return c.stop(&f) }
}

func (c *imageHookCtx) stop(key *func()) bool {
	c.mu.Lock()
	hook := c.onStop
	c.onStop = nil
	_, kept := c.funcs[key]
	if hook == nil {
		delete(c.funcs, key)
	}
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	return kept
}

// testImageDeadlineTimer admits, in a synctest bubble with the controlled clock following the bubble's clock, an
// instance whose D is RD, 100 ms after the admission's now: with no further call its deadline timer reads the clock
// once, 1 ns past D, and retires it with errImageExpired.
func testImageDeadlineTimer(t *testing.T) {
	f := newImageTestFixture(t, 1)
	round := f.round(t, imageTestLimits(time.Hour, 30*time.Minute+100*time.Millisecond), 0)
	t0 := f.clock.add(30 * time.Minute)
	f.clock.followRealTime(time.Now())
	inst := f.admitted(t, round, context.Background(), 0, 1, 1)
	reads := f.clock.readCount()
	time.Sleep(time.Second)
	synctest.Wait()
	_, end := f.ended(inst)
	after, last := f.clock.readCount(), f.clock.add(0)
	require(t, inst.deadline.Equal(t0.Add(100*time.Millisecond)) && end == errImageExpired && after == reads+1 && last.Equal(t0.Add(100*time.Millisecond+time.Nanosecond)), //nolint:errorlint // The recorded end is errImageExpired itself.
		"deadline timer: D %v end %v clock reads %d->%d last read %v, want D %v and %v after one read 1 ns past D", inst.deadline, end, reads, after, last, t0.Add(100*time.Millisecond), errImageExpired)
	f.requireOwners(t, round, 0, imageOneInstance(0), "deadline timer")
}

// imageBubble is an instance admitted in a synctest bubble on session 0 with ID 1, start 1 and
// AttemptLifetime 100 ms, with a cancellable round ctx and Request ctx.
type imageBubble struct {
	f                          *imageTestFixture
	round                      *ImageRound
	inst                       *imageInstance
	t0                         time.Time
	cancelRequest, cancelRound context.CancelFunc
}

// runImageBubble runs body on an imageBubble; with follow set, the controlled clock follows the bubble's fake clock from the admission on.
func runImageBubble(t *testing.T, follow bool, body func(t *testing.T, b imageBubble)) {
	inImageBubble(func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		t0, limits := f.clock.Now(), imageTestLimits(100*time.Millisecond)
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
	})(t)
}

// expire moves the controlled clock 1 ns past D, then runs passTimer.
func (b imageBubble) expire() {
	b.f.clock.set(b.t0.Add(100*time.Millisecond + time.Nanosecond))
	b.passTimer()
}

// passTimer lets the bubble's fake clock pass the deadline timer's duration, then returns after synctest.Wait.
func (b imageBubble) passTimer() {
	time.Sleep(time.Second)
	synctest.Wait()
}

// state returns whether the instance is retired, the controlled clock's read count and last value,
// the owner state on session 0 and the instance's recorded end.
func (b imageBubble) state() (bool, int, time.Time, imageOwners, error) {
	retired, end := b.f.ended(b.inst)
	owners := b.f.owners(b.round, 0)
	b.f.clock.mu.Lock()
	defer b.f.clock.mu.Unlock()
	return retired, b.f.clock.reads, b.f.clock.now, owners, end
}

// testImageTimerTick lets the fake clock run: the deadline timer fires its duration after admission,
// reads the clock once at D plus 1 ns and retires the instance with errImageExpired.
func testImageTimerTick(t *testing.T) {
	runImageBubble(t, true, func(t *testing.T, b imageBubble) {
		_, reads, _, _, _ := b.state()
		b.passTimer()
		retired, after, last, owners, end := b.state()
		want := b.t0.Add(100*time.Millisecond + time.Nanosecond)
		require(t, retired && end == errImageExpired && after == reads+1 && last.Equal(want) && owners == imageOneInstance(0), //nolint:errorlint // The recorded end is errImageExpired itself.
			"deadline timer: retired=%v end=%v clock reads %d->%d last read %v owner state %+v, want retired with %v after one read at %v", retired, end, reads, after, last, owners, errImageExpired, want)
	})
}

// testImageCallbackOrTimerAfterClose starts one ctx callback or the deadline timer after Close, with now short of D: it
// is refused a lease and reads no clock, retires and releases nothing, and its stop handle reports that it had started.
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
				retired, after, now, owners, end := b.state()
				require(t, !retired && end == nil && after == reads && now.Equal(b.t0) && owners == imageOneInstance(1) && b.f.instance(1) == b.inst, "callback or timer after close: retired=%v end=%v clock reads %d->%d now %v owner state %+v, want the instance current at %v and no clock read", retired, end, reads, after, now, owners, b.t0)
				req := b.f.lockRequester()
				stopped := tc.stop(b.inst)
				req.mu.Unlock()
				require(t, !stopped, "callback or timer after close: its stop handle stopped it, want it started before")
			})
		})
	}
}

// testImageRetirementStops retires the instance through one ctx callback; the other callback or the
// timer, stopped by that retirement, then does not run or read the clock.
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
				retired, reads, _, owners, end := b.state()
				require(t, retired && end == tc.end && owners == imageOneInstance(0), "first end: retired=%v end=%v owner state %+v, want retired with %v", retired, end, owners, tc.end) //nolint:errorlint // The recorded end is the first end's ctx error itself.
				tc.later(b)
				_, after, _, _, end := b.state()
				require(t, after == reads && end == tc.end, "callback or timer after retirement: clock reads %d->%d end %v, want no read and the end %v kept", reads, after, end, tc.end) //nolint:errorlint // The kept end is the first end's ctx error itself.
			})
		})
	}
}

// endRequest cancels the Request ctx and endRound the round ctx; both then return after synctest.Wait.
func (b imageBubble) endRequest() {
	b.cancelRequest()
	synctest.Wait()
}

func (b imageBubble) endRound() {
	b.cancelRound()
	synctest.Wait()
}

// testImageSaturatedTimer: in a synctest bubble, a deadline timer of the largest Duration has not
// fired two fake hours after admission: no clock read, the instance current and the timer armed.
func testImageSaturatedTimer(t *testing.T) {
	f := newImageTestFixture(t, 1)
	t0, limits := f.clock.Now(), imageTestLimits(math.MaxInt64, math.MaxInt64)
	inst := f.admitted(t, f.round(t, limits, 0), context.Background(), 0, 1, 1)
	require(t, inst.deadline.Sub(t0) == math.MaxInt64, "D-now=%v, want the largest Duration", inst.deadline.Sub(t0))
	reads := f.clock.readCount()
	time.Sleep(2 * time.Hour)
	synctest.Wait()
	req := f.lockRequester()
	armed := inst.timer.Stop()
	req.mu.Unlock()
	retired, _ := f.ended(inst)
	require(t, armed && !retired && f.instance(1) == inst && f.clock.readCount() == reads, "after two hours: timer armed=%v retired=%v clock reads %d->%d, want armed, current and no read", armed, retired, reads, f.clock.readCount())
}

// admitTimerSpent admits start with D a short time after now and returns the instance once its
// deadline timer has read the clock, as the third read after the admission read.
func (f *imageTestFixture) admitTimerSpent(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte, wantID uint64) *imageInstance {
	t.Helper()
	reads := f.clock.readCount()
	f.admitted(t, round, ctx, session, start, wantID)
	return f.requireTimerSpent(t, imageTestAnchor, start, reads+3)
}

// requireTimerSpent runs in a bubble: it waits for reads clock reads, the last of them the deadline timer's for the
// current instance of anchor and start, then for synctest.Wait, and checks under the requester mutex that the
// instance is unretired and its timer fired and was not armed again.
func (f *imageTestFixture) requireTimerSpent(t *testing.T, anchor ImageAnchor, start byte, reads int) *imageInstance {
	t.Helper()
	waitUntil(t, func() bool { return f.clock.readCount() >= reads }, "deadline timer read")
	synctest.Wait()
	req := f.lockRequester()
	inst := req.current[imageKey{anchor, imageStart(start)}]
	retired, rearmed := inst == nil, false
	if inst != nil {
		retired, rearmed = inst.retired, inst.timer.Stop()
	}
	req.mu.Unlock()
	require(t, !retired && !rearmed, "start %d after its timer read with now not after D: current instance %p, retired=%v, timer armed again=%v", start, inst, retired, rearmed)
	requireEqual(t, f.clock.readCount(), reads, "clock reads after the timer read")
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
		f.requireFault(t, 0, 1, os.ErrDeadlineExceeded.Error(), "after the failed write")
		requireImageResult(t, inHook, 1, 1, nil, "request in the close hook")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after the failed write")
		f.failedOnClosed(t, round, 0, 2, 2)
		f.requireFrames(t, 0, "after the failure")
	})
	t.Run("a request on the same session in the close hook of a failed write", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		round := f.round(t, imageTestLimits(), 0)
		inHook := imageResult{err: errImageNoResult}
		// The hook runs inside the failed request, whose own bound is lifecycleWatchdog.
		f.onClose(0, func() {
			inHook = requestWithin(lifecycleWatchdog/2, round, context.Background(), f.ids[0], 2, imageTestByteLimit)
		})
		f.wires[0].armStall().release <- errImageScriptedWrite
		requireImageResult(t, f.request(round, context.Background(), 0, 1), 1, 1, errImageScriptedWrite, "failed write")
		requireImageResult(t, inHook, 2, 2, nil, "request on the same session in the close hook")
		f.requireFrames(t, 0, "after the close hook", expectedImageQuery(2, 2))
		f.requireFault(t, 0, 1, errImageScriptedWrite.Error(), "after the failed write")
	})
	t.Run("a frame refused by the message size cap before its first byte", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		f.s.cfg.PeerRuntimeConfig.MaxMessageSize = 119
		round := f.round(t, imageTestLimits(), 0)
		got := f.request(round, context.Background(), 0, 1)
		require(t, got.q == expectedImageQuery(1, 1) && got.err != nil && got.err.Error() == "message exceeds cap", "cap refusal: q=%+v err=%v, want id 1 start 1 and the frame writer's cap refusal", got.q, got.err)
		written, _ := f.conns[0].snapshot()
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "after the cap refusal")
		require(t, len(written) == 0, "after the cap refusal: %d bytes written, want none", len(written))
		f.requireFault(t, 0, 1, got.err.Error(), "after the cap refusal")
	})
	for _, roundCtx := range []bool{false, true} {
		t.Run(fmt.Sprintf("a failed write with the round ctx %v reporting done before its callback runs", roundCtx), func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			c := newImageHookCtx()
			roundC, requestC := imageUnwindCtx(c, roundCtx)
			round := f.roundCtx(t, roundC, imageTestLimits(24*time.Hour, 48*time.Hour), 0)
			stall, pending := f.stalledRequest(t, round, requestC, 0, 1)
			inst := f.instance(1)
			c.end(errors.New("ctx ended with its callback not run"))
			stall.release <- errImageScriptedWrite
			requireImageResult(t, awaitImageResult(t, pending, "failed write"), 1, 1, errImageScriptedWrite, "failed write with a done ctx")
			retired, _ := f.ended(inst)
			require(t, retired, "instance after the failed write: retired=%v, want retired", retired)
			f.requireOwners(t, round, 0, imageOneInstance(0), "after the failed write")
			f.requireFault(t, 0, 1, errImageScriptedWrite.Error(), "after the failed write")
		})
	}
	t.Run("sibling stays current", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		round := f.round(t, imageTestLimits(), 0, 1)
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.wires[0].armStall().release <- errImageScriptedWrite
		requireImageResult(t, f.request(round, context.Background(), 0, 2), 2, 2, errImageScriptedWrite, "failed write")
		f.requireFault(t, 0, 1, errImageScriptedWrite.Error(), "after the failed write")
		f.requireUsage(t, round, 0, imageUsage(1, 2, 2, 2, 0), imageUsage(1, 2, 2, 2, 0), "after the failed write")
		f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
		f.admitted(t, round, context.Background(), 1, 2, 1)
		f.failedOnClosed(t, round, 0, 3, 3)
		f.requireFrames(t, 0, "session frames", expectedImageQuery(1, 1))
		f.requireUsage(t, round, 0, imageUsage(1, 3, 3, 3, 0), imageUsage(2, 3, 4, 4, 0), "after the later requests")
	})
}

func testImageStaleHandle(t *testing.T) {
	t.Run("a ctx callback started before a pass retired its instance runs after the replacement", inImageBubble(testImageStaleCallback))
	t.Run("write failure of an instance ended during the write", func(t *testing.T) {
		f := newImageTestFixture(t, 3)
		t0 := f.clock.Now()
		round := f.round(t, imageTestLimits(), 0, 1, 2)
		stall, pending := f.stalledRequest(t, round, context.Background(), 0, 1)
		f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
		replacement := f.admitted(t, round, context.Background(), 1, 1, 1)
		stall.release <- errImageScriptedWrite
		requireImageResult(t, awaitImageResult(t, pending, "failed write"), 1, 1, nil, "failed write after an end")
		f.requireFault(t, 0, 1, errImageScriptedWrite.Error(), "after the failed write")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after the failed write")
		f.refused(t, round, context.Background(), 2, 1, errImageAssignmentCurrent)
		require(t, f.instance(1) == replacement, "replacement retired by a stale write failure")
	})
}

// testImageStaleCallback cancels the first instance's ctx in the admission clock read of a request
// for the same start on another session, so its callback runs after the replacement is registered.
func testImageStaleCallback(t *testing.T) {
	f := newImageTestFixture(t, 3)
	limits := imageTestLimits(math.MaxInt64, math.MaxInt64)
	round := f.round(t, limits, 0, 1, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stale := f.admitted(t, round, ctx, 0, 1, 1)
	f.clock.cancelOnRead(cancel)
	f.admitted(t, round, context.Background(), 1, 1, 1)
	synctest.Wait()
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
	registry := f.owners(nil, 0)
	round, err := f.begin(ctx, config)
	require(t, round == nil && err == want, "%s: round=%v err=%v want %v", label, round != nil, err, want) //nolint:errorlint // The refusal is the wanted sentinel itself, not a wrapper.
	f.requireOwners(t, nil, 0, registry, label)
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
}

// testImageSourceBound compares the bytes BeginImageRound allocates for 1048576 unregistered source ids with the
// backing array of that list, which one table sized by the list exceeds.
func testImageSourceBound(t *testing.T) {
	f := newImageTestFixture(t, 2)
	config := f.config(imageTestLimits())
	config.SourceIDs = make([]string, 1<<20)
	for i := range config.SourceIDs {
		config.SourceIDs[i] = fmt.Sprintf("absent-%d:1", i)
	}
	backing := uint64(cap(config.SourceIDs)) * uint64(reflect.TypeFor[string]().Size())
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	round, err := f.s.BeginImageRound(context.Background(), config)
	runtime.ReadMemStats(&after)
	grown := after.TotalAlloc - before.TotalAlloc
	require(t, round == nil && errors.Is(err, errImageSourceSet) && grown < backing, "round=%v err=%v allocated %d bytes, source list backing array %d bytes", round != nil, err, grown, backing)
}

// testImageSourceDecision runs imageSources on a copy of Service.peers holding two sessions, the first also under
// its alias, and BeginImageRound on that Service, for one more ID than copied entries, an ID with no entry after
// the first logical address, that address and its alias, and both logical addresses.
func testImageSourceDecision(t *testing.T) {
	f, alias := newImageTestFixture(t, 2), "192.0.2.40:9"
	waitUntil(t, f.s.peersMu.TryRLock, "peersMu")
	peers := maps.Clone(f.s.peers)
	f.s.peersMu.RUnlock()
	require(t, len(peers) == 4 && peers[f.ids[0]] == f.peers[0] && peers[alias] == f.peers[0] && peers[f.ids[1]] == f.peers[1], "Service.peers copy %v, want 4 entries naming session 0 under %s and %s and session 1 under %s", peers, f.ids[0], alias, f.ids[1])
	for _, ids := range [][]string{append(slices.Sorted(maps.Keys(peers)), "absent:1"), {f.ids[0], "absent:1"}, {f.ids[0], alias}} {
		sources, err := imageSources(ids, peers)
		require(t, sources == nil && errors.Is(err, errImageSourceSet), "source decision for %q: sources=%v err=%v, want nil and %v", ids, sources, err, errImageSourceSet)
		f.requireRoundRefused(t, context.Background(), ImageRoundConfig{Anchor: imageTestAnchor, SourceIDs: ids, Limits: imageTestLimits()}, errImageSourceSet, fmt.Sprintf("round with %q", ids))
	}
	sources, err := imageSources([]string{f.ids[0], f.ids[1]}, peers)
	want := map[string]*peer{f.ids[0]: f.peers[0], f.ids[1]: f.peers[1]}
	require(t, err == nil && maps.Equal(sources, want), "source decision for both logical addresses: sources=%v err=%v, want %v", sources, err, want)
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
		f.refusedWith(t, round, context.Background(), f.ids[1], 1, 1, imageTestByteLimit, errImageUnknownSource)
		f.refusedWith(t, round, context.Background(), "absent:1", 0, 1, imageTestByteLimit, errImageUnknownSource)
		f.refusedWith(t, round, context.Background(), f.ids[1], 1, 1, 150904, errImageUnknownSource)
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
	t.Run("byte limit, round deadline, assignment, attempt, limit and id checks in order", inImageBubble(func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		t0, limits := f.clock.Now(), imageTestLimits()
		limits.PerPeer.AdmittedRequests, limits.AttemptLifetime = 2, 50*time.Millisecond
		round := f.round(t, limits, 0, 1)
		f.admitTimerSpent(t, round, context.Background(), 0, 1, 1)
		f.refused(t, round, context.Background(), 0, 1, errImageAssignmentCurrent)
		f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
		ctx, cancel := context.WithCancel(context.Background())
		inst := f.admitted(t, round, ctx, 0, 2, 2)
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
	}))
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
	limits := imageTestLimits(time.Hour, time.Hour)
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
	t.Run("caller's source list overwritten after the round began", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		config := f.config(imageTestLimits(), 0)
		round, err := f.begin(context.Background(), config)
		must(t, err, "BeginImageRound")
		config.SourceIDs[0] = "renamed:1"
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.requireFrames(t, 0, "original source id", expectedImageQuery(1, 1))
		f.refusedWith(t, round, context.Background(), "renamed:1", 0, 2, imageTestByteLimit, errImageUnknownSource)
	})
	t.Run("newer registration of the logical address", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		owner := f.serviceEntry(f.ids[0])
		require(t, owner == f.peers[0], "logical address names %p at round construction, want session %p", owner, f.peers[0])
		round := f.round(t, imageTestLimits(), 0)
		newer := f.addSession(t, f.ids[0], "192.0.2.81:9")
		owner = f.serviceEntry(f.ids[0])
		waitUntil(t, f.s.peersMu.TryRLock, "peersMu")
		_, live := f.s.livePeers[f.peers[0]]
		f.s.peersMu.RUnlock()
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
		req := f.lockRequester()
		closed := lifecycleClose(f.s)
		requireChannelClosed(t, f.conns[0].closed, "connection close")
		requireStillBlocked(t, closed, "Close with the parked request's end decision pending")
		var nilCtx context.Context
		drainedNil := requestWithin(lifecycleWatchdog, round, nilCtx, f.ids[0], 3, imageTestByteLimit)
		drained := requestWithin(lifecycleWatchdog, round, context.Background(), f.ids[0], 2, imageTestByteLimit)
		drainedRound, err := f.begin(context.Background(), f.config(imageTestLimits(), 0))
		req.mu.Unlock()
		requireQueryResult(t, drainedNil, consensus.UTXOImageQuery{}, errServiceClosed, "request with a nil ctx while Close drains")
		requireQueryResult(t, drained, consensus.UTXOImageQuery{}, errServiceClosed, "request while Close drains")
		require(t, drainedRound == nil && err == errServiceClosed, "round while Close drains: round=%v err=%v, want %v", drainedRound != nil, err, errServiceClosed) //nolint:errorlint // The refusal is errServiceClosed itself.
		requireReturned(t, closed, "Close")
		f.requireOwners(t, round, 0, imageOneInstance(0), "after the drained refusals at Close return")
		retired, end := f.ended(inst)
		require(t, retired && end == errImageExpired, "at Close return: retired=%v end=%v", retired, end) //nolint:errorlint // The recorded end is errImageExpired itself.
		requireImageResult(t, awaitImageResult(t, pending, "parked request"), 1, 1, errImageExpired, "parked request")
		_ = release()
		f.requireFrames(t, 0, "parked request")
	})
	t.Run("a request whose admission clock read returns after Close started", func(t *testing.T) { testImageDrainAdmission(t, false) })
	t.Run("a request whose ctx is canceled at an admission clock read that returns after Close started", func(t *testing.T) { testImageDrainAdmission(t, true) })
	t.Run("a request whose lifecycle read returned OPEN completes as admitted when Close starts during its admission", testImageDrainAfterOpenRead)
	t.Run("a round whose clock read returns after Close started", func(t *testing.T) { testImageDrainRound(t, false) })
	t.Run("a round with an inexact RD whose clock read returns after Close started", func(t *testing.T) { testImageDrainRound(t, true) })
	t.Run("request write failed by close", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		round := f.round(t, imageTestLimits(), 0)
		requestClose, gate := make(chan struct{}), make(chan struct{})
		closers := f.recordClosers(round, 0, func() { close(requestClose); <-gate })
		_, pending := f.stalledRequest(t, round, context.Background(), 0, 1)
		closed := lifecycleClose(f.s)
		requireChannelClosed(t, requestClose, "connection close by the failed request")
		requireStillBlocked(t, closed, "Close with the failed request's connection close pending")
		want := []imageCloser{{}, {request: true, lastError: net.ErrClosed.Error(), perPeer: imageUsage(0, 1, 1, 1, 0), global: imageUsage(0, 1, 1, 1, 0)}}
		got := closers()
		require(t, slices.Equal(got, want) && f.closes(0) == 2, "connection closes before Close returns=%+v count %d, want %+v and 2", got, f.closes(0), want)
		close(gate)
		requireReturned(t, closed, "Close")
		f.requireOwners(t, round, 0, imageOneInstance(0), "at Close return")
		f.requireFault(t, 0, 2, net.ErrClosed.Error(), "at Close return")
		requireImageResult(t, awaitImageResult(t, pending, "failed write"), 1, 1, net.ErrClosed, "failed write")
		f.requireFrames(t, 0, "failed write")
	})
}

// blockNextRead makes the next clock read wait for release, then run onRelease and return at of
// the clock's time. entered is closed when that read starts waiting.
func (f *imageTestFixture) blockNextRead(at func(time.Time) time.Time, onRelease func()) (entered <-chan struct{}, release func()) {
	in, out := make(chan struct{}), make(chan struct{})
	f.clock.onNextRead(func(now time.Time) time.Time {
		close(in)
		<-out
		onRelease()
		return at(now)
	})
	return in, func() { close(out) }
}

// closeWhileReadHeld starts Close once the held clock read has started, waits until Close has
// published the non-OPEN state, checks that Close stays blocked and then releases the read.
func (f *imageTestFixture) closeWhileReadHeld(t *testing.T, entered <-chan struct{}, release func()) chan error {
	t.Helper()
	requireChannelClosed(t, entered, "held clock read")
	closed := lifecycleClose(f.s)
	waitDraining(t, f.s)
	requireStillBlocked(t, closed, "Close with the clock read held")
	release()
	return closed
}

// testImageDrainAdmission releases the held admission clock read of a request, after Close started,
// past an instance's D and, with canceled set, with its ctx canceled: the request, which holds the
// requester mutex during that read, refuses with errServiceClosed, ahead of its ctx check and its
// pass, and the instance stays current.
func testImageDrainAdmission(t *testing.T, canceled bool) {
	f := newImageTestFixture(t, 2)
	t0, limits := f.clock.Now(), imageTestLimits(24*time.Hour, 48*time.Hour)
	round := f.round(t, limits, 0, 1)
	first := f.admitted(t, round, context.Background(), 0, 1, 1)
	refusing := f.owners(round, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	onRelease := func() {}
	if canceled {
		onRelease = cancel
	}
	entered, release := f.blockNextRead(func(time.Time) time.Time { return t0.Add(24*time.Hour + time.Nanosecond) }, onRelease)
	pending := f.goRequest(round, ctx, 1, 1)
	requireChannelClosed(t, entered, "held admission clock read")
	unlocked := f.s.imageRequester.mu.TryLock()
	if unlocked {
		f.s.imageRequester.mu.Unlock()
	}
	closed := f.closeWhileReadHeld(t, entered, release)
	require(t, !unlocked, "the requester mutex was free while the admission clock read was held")
	requireQueryResult(t, awaitImageResult(t, pending, "drained admission"), consensus.UTXOImageQuery{}, errServiceClosed, "admission after Close started")
	requireReturned(t, closed, "Close")
	f.requireCurrentAfterUnwind(t, round, first)
	f.requireOwners(t, round, 1, refusing, "drained admission")
	f.requireFrames(t, 1, "drained admission")
}

// testImageDrainAfterOpenRead holds the second Err call of the request ctx, the admission's re-read under the requester
// mutex after its lifecycle read returned OPEN and before its pass, until Close has published the non-OPEN state and
// closed the connection: the request completes as admitted, its one write attempt fails with net.ErrClosed, and
// Close returns after it with the usage released.
func testImageDrainAfterOpenRead(t *testing.T) {
	f := newImageTestFixture(t, 1)
	round := f.round(t, imageTestLimits(24*time.Hour, 48*time.Hour), 0)
	c, entered, release := newImageHookCtx(), make(chan struct{}), make(chan struct{})
	c.onSecondErr = func() { close(entered); <-release }
	pending := f.goRequest(round, c, 0, 1)
	requireChannelClosed(t, entered, "second Err call of the request ctx")
	closed := lifecycleClose(f.s)
	waitDraining(t, f.s)
	requireChannelClosed(t, f.conns[0].closed, "connection close by Close")
	requireStillBlocked(t, closed, "Close with the admission held")
	close(release)
	requireImageResult(t, awaitImageResult(t, pending, "admission held across Close"), 1, 1, net.ErrClosed, "admission held across Close")
	requireReturned(t, closed, "Close")
	f.requireOwners(t, round, 0, imageOneInstance(0), "at Close return")
	f.requireFault(t, 0, 2, net.ErrClosed.Error(), "at Close return")
	attempted, _ := f.conns[0].snapshot()
	require(t, len(attempted) == wireHeaderSize && len(f.wires[0].bytes()) == 0, "write attempts of %d bytes with %d accepted, want the %d header bytes and none", len(attempted), len(f.wires[0].bytes()), wireHeaderSize)
}

// testImageDrainRound releases the held clock read of BeginImageRound after Close started, with
// inexact set at a monotonic now with an inexact RD: it refuses with errServiceClosed.
func testImageDrainRound(t *testing.T, inexact bool) {
	start, limits := time.Unix(1_800_000_000, 0), imageTestLimits()
	if inexact {
		start, limits.RoundLifetime = time.Now(), math.MaxInt64
	}
	f := newImageTestFixtureAt(t, 1, start)
	registry := f.owners(nil, 0)
	entered, release := f.blockNextRead(func(now time.Time) time.Time {
		if inexact {
			return time.Now()
		}
		return now
	}, func() {})
	done := make(chan imageBegin, 1)
	go func() {
		round, err := f.s.BeginImageRound(context.Background(), f.config(limits, 0))
		done <- imageBegin{round, err}
	}()
	closed := f.closeWhileReadHeld(t, entered, release)
	got, ok := receiveWithin(done, lifecycleWatchdog)
	require(t, ok && got.round == nil && got.err == errServiceClosed, "round after Close started: returned=%v round=%v err=%v, want %v", ok, got.round != nil, got.err, errServiceClosed) //nolint:errorlint // The refusal is errServiceClosed itself.
	requireReturned(t, closed, "Close")
	f.requireOwners(t, nil, 0, registry, "round after Close started")
}

// imageCloser is one Close of a session connection: whether it ran inside a Request call, and,
// for one that did, the session's last error and the round's usage at that Close.
type imageCloser struct {
	request         bool
	lastError       string
	perPeer, global imageUnitVector
}

// recordClosers records every later Close of session's connection, runs inRequest after recording
// a Close made inside a Request call and returns the records so far.
func (f *imageTestFixture) recordClosers(round *ImageRound, session int, inRequest func()) func() []imageCloser {
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
		if record.request {
			inRequest()
		}
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
	t.Run("a panic in the AfterFunc method of the request ctx at admission", func(t *testing.T) { testImageUnwindArming(t, false, false) })
	t.Run("runtime.Goexit in the AfterFunc method of the request ctx at admission", func(t *testing.T) { testImageUnwindArming(t, true, false) })
	t.Run("a panic in the AfterFunc method of the round ctx at admission", func(t *testing.T) { testImageUnwindArming(t, false, true) })
	t.Run("runtime.Goexit in the AfterFunc method of the round ctx at admission", func(t *testing.T) { testImageUnwindArming(t, true, true) })
	t.Run("a panic in the stop call of the pre-write retirement with D before RD", func(t *testing.T) { testImageUnwindStop(t, false, false, false) })
	t.Run("a panic in the stop call of the pre-write retirement at RD with D equal to RD", func(t *testing.T) { testImageUnwindStop(t, true, false, false) })
	t.Run("a panic in the round ctx stop call of the pre-write retirement with D before RD", func(t *testing.T) { testImageUnwindStop(t, false, true, false) })
	t.Run("a panic in the request ctx stop call of another request's pass retiring the instance", func(t *testing.T) { testImageUnwindStop(t, false, false, true) })
	t.Run("a panic in the round ctx stop call of another request's pass retiring the instance", func(t *testing.T) { testImageUnwindStop(t, false, true, true) })
	t.Run("a panic in the request ctx stop call of the retirement after a failed write", func(t *testing.T) { testImageUnwindFailedWrite(t, false, false) })
	t.Run("runtime.Goexit in the request ctx stop call of the retirement after a failed write", func(t *testing.T) { testImageUnwindFailedWrite(t, true, false) })
	t.Run("a panic in the round ctx stop call of the retirement after a failed write", func(t *testing.T) { testImageUnwindFailedWrite(t, false, true) })
}

// imageUnwindCtx returns the round ctx and the Request ctx of a test with the imageHookCtx C: C as
// the Request ctx, or, with roundCtx set, as the round ctx with the Request ctx live.
func imageUnwindCtx(c *imageHookCtx, roundCtx bool) (context.Context, context.Context) {
	if roundCtx {
		return c, context.Background()
	}
	return context.Background(), c
}

// imageUnwinder returns a func that calls runtime.Goexit, with goexit set, or else panics with imageUnwindSentinel.
func imageUnwinder(goexit bool) func() {
	return func() {
		if goexit {
			runtime.Goexit()
		}
		panic(imageUnwindSentinel)
	}
}

// requireUnwound runs the request for start 1 on session 0 with ctx and checks that it ended by
// runtime.Goexit, with goexit set, or else by a panic with imageUnwindSentinel.
func (f *imageTestFixture) requireUnwound(t *testing.T, round *ImageRound, ctx context.Context, goexit bool) {
	t.Helper()
	if goexit {
		require(t, f.requestExited(t, round, ctx, 0, 1), "request returned instead of exiting its goroutine")
		return
	}
	recovered := f.requestRecovered(t, round, ctx, 0, 1)
	require(t, recovered == imageUnwindSentinel, "recovered %v, want %q", recovered, imageUnwindSentinel)
}

// requireCurrentAfterUnwind checks that inst is the registered instance of start 1, unretired with
// no end, and that round's current-assignment usage on session 0 is 1.
func (f *imageTestFixture) requireCurrentAfterUnwind(t *testing.T, round *ImageRound, inst *imageInstance) {
	t.Helper()
	retired, end := f.ended(inst)
	perPeer, _ := f.usage(round, 0)
	require(t, inst != nil && f.instance(1) == inst && !retired && end == nil && perPeer[unitCurrentAssignments] == 1, "after the unwind: registered=%v retired=%v end=%v current assignments %d, want registered, unretired, no end and 1", f.instance(1) == inst, retired, end, perPeer[unitCurrentAssignments])
}

// testImageUnwindFailedWrite fails the payload write after the 24-byte header and unwinds the
// post-write retirement at the first stop call of the imageHookCtx C: the pending request bytes are
// 0 at the close, which happens once with the write error recorded, and the instance read during
// the payload write stays current.
func testImageUnwindFailedWrite(t *testing.T, goexit, roundCtx bool) {
	f := newImageTestFixture(t, 2)
	limits := imageUnwindLimits(24*time.Hour, 48*time.Hour)
	c := newImageHookCtx()
	c.onStop = imageUnwinder(goexit)
	roundC, requestC := imageUnwindCtx(c, roundCtx)
	round := f.roundCtx(t, roundC, limits, 0, 1)
	stall := f.wires[0].armStallAfter(1)
	var inst *imageInstance
	go func() { <-stall.entered; inst = f.instance(1); stall.release <- errImageScriptedWrite }()
	pending := uint64(math.MaxUint64)
	// A close made under the requester mutex blocks this hook past the request's lifecycleWatchdog bound.
	f.onClose(0, func() {
		f.s.imageRequester.mu.Lock()
		pending = round.usageFor(f.peers[0])[unitPendingNetworkBytes]
		f.s.imageRequester.mu.Unlock()
	})
	f.requireUnwound(t, round, requestC, goexit)
	require(t, len(f.wires[0].bytes()) == wireHeaderSize, "after the unwind: %d bytes written, want the %d header bytes", len(f.wires[0].bytes()), wireHeaderSize)
	f.requireFault(t, 0, 1, errImageScriptedWrite.Error(), "after the unwind")
	requireEqual(t, pending, 0, "pending request bytes inside the close hook")
	f.requireCurrentAfterUnwind(t, round, inst)
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	requireReturned(t, lifecycleClose(f.s), "Close")
}

// imageUnwindLimits is imageTestLimits with the given lifetimes and 120 pending request bytes per peer and globally.
func imageUnwindLimits(lifetimes ...time.Duration) ImageLimits {
	limits := imageTestLimits(lifetimes...)
	limits.PerPeer.PendingNetworkBytes, limits.Global.PendingNetworkBytes = 120, 120
	return limits
}

// unwindAtPreWriteRead makes the first later clock read made by a pre-write decision call unwind;
// the reads before it leave the clock unchanged.
func (f *imageTestFixture) unwindAtPreWriteRead(unwind func()) {
	f.clock.onReadFrom(".(*ImageRound).endBeforeWrite", func(now time.Time) time.Time { unwind(); return now })
}

// goRecovered requests start on session with ctx on its own goroutine and delivers the value the
// call panicked with, or nil when it returned.
func (f *imageTestFixture) goRecovered(round *ImageRound, ctx context.Context, session int, start byte) <-chan any {
	done := make(chan any, 1)
	go func() {
		var recovered any
		defer func() { done <- recovered }()
		defer func() { recovered = recover() }()
		_, _ = round.Request(ctx, f.ids[session], imageStart(start), imageTestByteLimit)
	}()
	return done
}

// requestRecovered requests start on session with ctx and returns the value the call panicked
// with, or nil when it returned, failing the test when it has not ended within lifecycleWatchdog.
func (f *imageTestFixture) requestRecovered(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte) any {
	t.Helper()
	return awaitImageResult(t, f.goRecovered(round, ctx, session, start), "unwinding request")
}

// requestExited requests start on session with ctx on its own goroutine and reports whether that
// goroutine ended without the call returning.
func (f *imageTestFixture) requestExited(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte) bool {
	t.Helper()
	returned := false
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		_, _ = round.Request(ctx, f.ids[session], imageStart(start), imageTestByteLimit)
		returned = true
	}()
	requireChannelClosed(t, ended, "request goroutine end")
	return !returned
}

// requireNextAfterUnwind requests start on session and checks the query with wantID and nil and one
// frame for it; the request's ctx is canceled at cleanup.
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
	f.requireFault(t, session, 0, "", "after the unwind")
	requireReturned(t, lifecycleClose(f.s), "Close")
}

// testImageUnwindWithWriteMu unwinds the request for start 1 on session 0, with writeMu free, at
// the clock read its pre-write decision makes with writeMu acquired, by a panic or runtime.Goexit.
func testImageUnwindWithWriteMu(t *testing.T, goexit bool) {
	f := newImageTestFixture(t, 2)
	round := f.round(t, imageUnwindLimits(), 0, 1)
	f.unwindAtPreWriteRead(imageUnwinder(goexit))
	f.requireUnwound(t, round, context.Background(), goexit)
	f.requireFrames(t, 0, "after the unwind")
	f.requireNextAfterUnwind(t, round, 0, 2, 2)
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.requireNoFaultBeforeClose(t, 0)
}

// testImageUnwindWaiting unwinds a request at a pre-write clock read after a failed TryLock of the
// writeMu the test holds; the next request writes its frame only after the test releases it. The test
// unlocks writeMu only after three pre-write clock reads of that request, the second of which follows
// a failed TryLock made after the first, so the test still holds it; that request's ctx ends at cleanup.
func testImageUnwindWaiting(t *testing.T) {
	f := newImageTestFixture(t, 1)
	round := f.round(t, imageUnwindLimits(), 0)
	session := f.peers[0]
	session.writeMu.Lock()
	f.unwindAtPreWriteRead(func() { panic(imageUnwindSentinel) })
	f.requireUnwound(t, round, context.Background(), false)
	pending := f.goRequest(round, t.Context(), 0, 2)
	f.waitAdmitted(t, 0, 2, "request after the unwind")
	_, returned := receiveWithin(pending, lifecycleSettle)
	f.requireFrames(t, 0, "while the test holds writeMu")
	require(t, !returned, "request after the unwind returned while the test held writeMu")
	for range 3 {
		requireChannelClosed(t, f.clock.readFrom(".(*ImageRound).endBeforeWrite"), "pre-write clock read of the request waiting for writeMu")
	}
	session.writeMu.Unlock()
	requireImageResult(t, awaitImageResult(t, pending, "request after the unwind"), 2, 2, nil, "request after the unwind")
	f.requireFrames(t, 0, "after the test released writeMu", expectedImageQuery(2, 2))
	requireReturned(t, lifecycleClose(f.s), "Close")
}

// testImageUnwindWrite makes the connection write of the request frame for start 1 on session 0 panic before it records a byte.
func testImageUnwindWrite(t *testing.T) {
	f := newImageTestFixture(t, 1)
	round := f.round(t, imageUnwindLimits(), 0)
	f.wires[0].armPanic(imageUnwindSentinel)
	f.requireUnwound(t, round, context.Background(), false)
	requireEqual(t, len(f.wires[0].bytes()), 0, "bytes written by the panicking write")
	f.requireNextAfterUnwind(t, round, 0, 2, 2)
	f.requireNoFaultBeforeClose(t, 0)
}

// testImageUnwindArming unwinds a request, in a synctest bubble, at the first AfterFunc call of C,
// its Request ctx or, with roundCtx set, its round ctx: the next two requests leave the usage of a
// fresh Service, and, with roundCtx set, canceling the Request ctx Cr then changes nothing.
func testImageUnwindArming(t *testing.T, goexit, roundCtx bool) {
	inImageBubble(func(t *testing.T) {
		c := newImageHookCtx()
		c.onAfterFunc = imageUnwinder(goexit)
		cr, cancelCr := context.WithCancel(context.Background())
		// Registered ahead of the Service's Close cleanup, so it runs after that Close.
		t.Cleanup(cancelCr)
		roundC, requestC := context.Context(context.Background()), context.Context(c)
		if roundCtx {
			roundC, requestC = c, cr
		}
		f := newImageTestFixture(t, 2)
		round := f.roundCtx(t, roundC, imageUnwindLimits(), 0, 1)
		f.requireUnwound(t, round, requestC, goexit)
		f.requireNextAfterUnwind(t, round, 0, 1, 1)
		f.admitted(t, round, context.Background(), 0, 2, 2)
		g := newImageTestFixture(t, 2)
		fresh := g.round(t, imageUnwindLimits(), 0, 1)
		g.admitted(t, fresh, context.Background(), 0, 1, 1)
		g.admitted(t, fresh, context.Background(), 0, 2, 2)
		wantPerPeer, wantGlobal := g.usage(fresh, 0)
		f.requireUsage(t, round, 0, wantPerPeer, wantGlobal, "after the next requests")
		if roundCtx {
			cancelCr()
			synctest.Wait()
			f.requireUsage(t, round, 0, wantPerPeer, wantGlobal, "after Cr is canceled")
			f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
			inst := f.instance(1)
			require(t, inst != nil, "no current instance of start 1 after Cr is canceled")
			retired, end := f.ended(inst)
			require(t, !retired && end == nil, "instance of start 1 after Cr is canceled: retired=%v end=%v, want current", retired, end)
		}
		requireReturned(t, lifecycleClose(f.s), "Close")
	})(t)
}

// testImageUnwindStop unwinds a retirement of the instance of start 1 on session 0 at the first stop call of the
// imageHookCtx C, its Request ctx or round ctx, with now past D or, with atRD set, at RD with D equal to RD: with
// pass set the retirement is the pass of a request for start 2 on session 1, else the pre-write decision of the
// instance's own request waiting for writeMu. The instance stays current and a later pass retires it as expired.
func testImageUnwindStop(t *testing.T, atRD, roundCtx, pass bool) {
	f := newImageTestFixture(t, 2)
	t0 := f.clock.Now()
	limits := imageUnwindLimits(24*time.Hour, 48*time.Hour)
	end := t0.Add(24*time.Hour + time.Nanosecond)
	if atRD {
		limits.RoundLifetime, end = 24*time.Hour, t0.Add(24*time.Hour)
	}
	c := newImageHookCtx()
	c.onStop = func() { panic(imageUnwindSentinel) }
	roundC, _ := imageUnwindCtx(c, roundCtx)
	round := f.roundCtx(t, roundC, limits, 0, 1)
	inst, recovered, release := f.unwindRetirement(t, round, c, roundCtx, end, pass)
	require(t, recovered == imageUnwindSentinel, "recovered %v, want %q", recovered, imageUnwindSentinel)
	f.requireCurrentAfterUnwind(t, round, inst)
	f.requireUsage(t, round, 0, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 1, 1, 0), "after the stop call unwound")
	next := round
	if atRD {
		next = f.round(t, limits, 0, 1)
		f.refused(t, next, context.Background(), 1, 1, errImageAssignmentCurrent)
		f.clock.add(time.Nanosecond)
	}
	f.admitted(t, next, context.Background(), 1, 1, 1)
	_, recorded := f.ended(inst)
	require(t, recorded == errImageExpired, "unwound instance end after the next request=%v, want %v", recorded, errImageExpired) //nolint:errorlint // The recorded end is errImageExpired itself.
	if !atRD {
		f.requireUsage(t, round, 1, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after session 1's request")
	}
	release()
	f.requireNoFaultBeforeClose(t, 0)
}

// unwindRetirement makes a retirement of the instance of start 1 on session 0, admitted with the Request ctx that
// imageUnwindCtx gives for c, run with now at end and returns that instance, the value its unwinding caller panicked
// with and a func the test calls before Close: with pass set the caller is a request for start 2 on session 1, whose
// pass runs at end; else it is the instance's own request, waiting for the writeMu the test holds until that func runs.
func (f *imageTestFixture) unwindRetirement(t *testing.T, round *ImageRound, c *imageHookCtx, roundCtx bool, end time.Time, pass bool) (*imageInstance, any, func()) {
	t.Helper()
	_, ctx := imageUnwindCtx(c, roundCtx)
	if pass {
		inst := f.admitted(t, round, ctx, 0, 1, 1)
		f.clock.set(end)
		return inst, f.requestRecovered(t, round, context.Background(), 1, 2), func() {}
	}
	session := f.peers[0]
	session.writeMu.Lock()
	unwound := f.goRecovered(round, ctx, 0, 1)
	f.waitAdmitted(t, 0, 1, "request waiting for writeMu")
	inst := f.instance(1)
	f.clock.set(end)
	recovered := awaitImageResult(t, unwound, "request waiting for writeMu")
	return inst, recovered, func() { _ = session.writeMu.TryLock(); session.writeMu.Unlock() }
}
