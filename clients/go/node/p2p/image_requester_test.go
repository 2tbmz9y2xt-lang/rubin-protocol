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
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"
	"weak"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// imageTestClock is a counting ServiceConfig.Now; onRead runs once on the next read and sets the time.
type imageTestClock struct {
	t              *testing.T
	mu             sync.Mutex
	now            time.Time
	reads          int
	onRead         func(time.Time) time.Time
	base, realFrom time.Time
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
func (c *imageTestClock) set(now time.Time) { c.mu.Lock(); c.moveLocked(now); c.mu.Unlock() }
func (c *imageTestClock) add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.moveLocked(c.now.Add(d))
	return c.now
}
func (c *imageTestClock) readCount() int { c.mu.Lock(); defer c.mu.Unlock(); return c.reads }
func (c *imageTestClock) onNextRead(hook func(time.Time) time.Time) {
	c.mu.Lock()
	c.onRead = hook
	c.mu.Unlock()
}

func (c *imageTestClock) followRealTime(from time.Time) {
	c.mu.Lock()
	c.base, c.realFrom = c.now, from
	c.mu.Unlock()
}

// inImageBubble runs body in its own synctest bubble and fails t when the bubble ends with a goroutine blocked in it.
func inImageBubble(body func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		defer func() { r := recover(); require(t, r == nil, "synctest bubble: %v", r) }()
		synctest.Test(t, body)
	}
}

// imageSpin yields until cond holds and fails t after 1<<24 yields, a bound that does not use a bubble clock.
func imageSpin(t *testing.T, cond func() bool, label string) {
	t.Helper()
	for yields := 0; !cond(); yields++ {
		require(t, yields < 1<<24, "%s did not happen within 1<<24 yields", label)
		runtime.Gosched()
	}
}

func (c *imageTestClock) cancelOnRead(cancel func()) { c.jumpOnRead(time.Time{}, cancel) }
func (c *imageTestClock) jumpOnRead(now time.Time, cancel func()) {
	c.onNextRead(func(at time.Time) time.Time { cancel(); return cmp.Or(now, at) })
}

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

func (c *imageTestClock) readFrom(suffix string) <-chan struct{} {
	read := make(chan struct{})
	c.onReadFrom(suffix, func(now time.Time) time.Time { close(read); return now })
	return read
}

// imageWire records the writes of one session connection; an armed stall blocks a write until it receives a result or
// the connection closes, an armed panic panics before a byte is recorded, and a write after the close fails.
type imageWire struct {
	mu        sync.Mutex
	sent      []byte
	stall     *imageStall
	stallSkip int
	panicNext any
	panicSkip int
	closed    <-chan struct{}
}

type imageStall struct {
	entered chan struct{}
	release chan error
}

func (w *imageWire) write(b []byte) (int, error) {
	if isClosed(w.closed) {
		return 0, net.ErrClosed
	}
	w.mu.Lock()
	stall, value := w.stall, w.panicNext
	if w.panicSkip > 0 {
		w.panicSkip, value = w.panicSkip-1, nil
	} else {
		w.panicNext = nil
	}
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
			if err == errImageWritePanic { //nolint:errorlint // The sentinel itself selects the panic.
				panic(imageUnwindSentinel)
			}
			if err != nil {
				return 0, err
			}
		case <-w.closed:
		}
		if isClosed(w.closed) {
			return 0, net.ErrClosed
		}
	}
	w.mu.Lock()
	w.sent = append(w.sent, b...)
	w.mu.Unlock()
	return len(b), nil
}

func (w *imageWire) armStallAfter(skip int) *imageStall {
	stall := &imageStall{entered: make(chan struct{}), release: make(chan error, 1)}
	w.mu.Lock()
	w.stall, w.stallSkip = stall, skip
	w.mu.Unlock()
	return stall
}

func (w *imageWire) drop(n int)    { w.mu.Lock(); w.sent = w.sent[n:]; w.mu.Unlock() }
func (w *imageWire) bytes() []byte { w.mu.Lock(); defer w.mu.Unlock(); return bytes.Clone(w.sent) }

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

func newImageTestFixtureAt(t *testing.T, sessions int, start time.Time) *imageTestFixture {
	t.Helper()
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	f := &imageTestFixture{t: t, h: h, s: h.service, clock: &imageTestClock{t: t, now: start}}
	t.Cleanup(func() {
		requireReturned(t, lifecycleClose(f.s), "Close at cleanup")
		req := f.lockRequester()
		defer req.mu.Unlock()
		for _, inst := range req.current {
			req.retireLocked(inst, context.Canceled)
		}
	})
	f.s.cfg.Now = f.clock.Now
	f.s.cfg.PeerRuntimeConfig.WriteDeadline = 0
	for i := 0; i < sessions; i++ {
		f.addSession(t, fmt.Sprintf("image-peer:1911%d", i), fmt.Sprintf("192.0.2.%d:9", 40+i))
	}
	return f
}

func (f *imageTestFixture) addSession(t *testing.T, addr, endpoint string) int {
	t.Helper()
	p, conn := daRelayTestPeer(f.h, addr, endpoint), newBlockRetryConn(&scriptedConn{remote: stubAddr(endpoint)})
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

// imageTestLimits has large limits, Backoff 1 s, and AttemptLifetime and RoundLifetime, by default 10 s and 1 hour.
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

func newImageRound(t *testing.T, n int, sources ...int) (*imageTestFixture, *ImageRound) {
	f := newImageTestFixture(t, n)
	return f, f.round(t, imageTestLimits(), sources...)
}

func (f *imageTestFixture) round(t *testing.T, limits ImageLimits, sources ...int) *ImageRound {
	t.Helper()
	return f.roundCtx(t, context.Background(), limits, sources...)
}

// imageStart is the start key with b in its first byte below 0x80, else in its last byte.
func imageStart(b byte) (start [36]byte) { start[b>>7*35] = b; return start }

func expectedImageQuery(id uint64, start byte) consensus.UTXOImageQuery {
	return consensus.UTXOImageQuery{RequestID: id, Height: 7, BlockHash: [32]byte{0xb1}, Root: [32]byte{0x52}, StartKey: imageStart(start), ByteLimit: imageTestByteLimit}
}

type imageResult struct {
	q   consensus.UTXOImageQuery
	err error
}

func receiveWithin[T any](done <-chan T, bound time.Duration) (T, bool) {
	select {
	case v := <-done:
		return v, true
	case <-time.After(bound):
		var zero T
		return zero, false
	}
}

func callWithin[T any](t *testing.T, label string, call func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- call() }()
	return awaitImageResult(t, done, label)
}

var (
	errImageNoResult      = errors.New("request did not return within its bound")
	errImageScriptedWrite = errors.New("scripted write failure")
	// errImageWritePanic released into a stall makes that write panic with imageUnwindSentinel.
	errImageWritePanic                   = errors.New("image test write panic")
	errImageRequestEnd, errImageRoundEnd = errors.New("request ctx ended"), errors.New("round ctx ended")
	imageNilCtx                          context.Context
)

func launch(round *ImageRound, ctx context.Context, sourceID string, start byte, byteLimit uint32) <-chan imageResult {
	done := make(chan imageResult, 1)
	go func() {
		q, err := round.Request(ctx, sourceID, imageStart(start), byteLimit)
		done <- imageResult{q, err}
	}()
	return done
}

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

func awaitImageResult[T any](t *testing.T, done <-chan T, label string) T {
	t.Helper()
	result, ok := receiveWithin(done, lifecycleWatchdog)
	require(t, ok, "%s did not return within %s", label, lifecycleWatchdog)
	return result
}

func requireQueryResult(t *testing.T, got imageResult, want consensus.UTXOImageQuery, wantErr error, label string) {
	t.Helper()
	ok := got.q == want && got.err == wantErr //nolint:errorlint // The returned error is wantErr itself, not a value that wraps it.
	require(t, ok, "%s: q=%+v err=%v, want q=%+v err=%v", label, got.q, got.err, want, wantErr)
}

func requireImageResult(t *testing.T, got imageResult, wantID uint64, start byte, wantErr error, label string) {
	t.Helper()
	requireQueryResult(t, got, expectedImageQuery(wantID, start), wantErr, label)
}

func (f *imageTestFixture) admitted(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte, wantID uint64) *imageInstance {
	t.Helper()
	requireImageResult(t, f.request(round, ctx, session, start), wantID, start, nil, fmt.Sprintf("request session %d start %d", session, start))
	inst := f.instance(start)
	require(t, inst != nil, "request session %d start %d: no current instance", session, start)
	return inst
}

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

// imageOwners is the state a refusal leaves unchanged: the wrapping sum of the last request IDs, the registry size,
// the round's usage on one session and in total, and its attempted and start marks.
type imageOwners struct {
	ids                       uint64
	current, idKeys, peerKeys int
	peerKey                   bool
	perPeer, global           imageUnitVector
	attempted, starts         int
}

type imageFault struct {
	closes    int
	lastError string
	banScore  int
}

type imageSnapshot struct {
	imageOwners
	imageFault
	wire int
}

func imageOneInstance(current int) imageOwners {
	usage := imageUsage(uint64(current), 1, 1, 1, 0)
	return imageOwners{ids: 1, current: current, idKeys: 1, peerKeys: 1, peerKey: true, perPeer: usage, global: usage, attempted: 1, starts: 1}
}

func (f *imageTestFixture) lockRequester() *imageRequester {
	f.t.Helper()
	req := f.s.imageRequester
	imageSpin(f.t, req.mu.TryLock, "requester mutex")
	return req
}

func (f *imageTestFixture) fault(session int) imageFault {
	f.t.Helper()
	p := f.peers[session]
	imageSpin(f.t, p.stateMu.TryLock, "peer state mutex")
	defer p.stateMu.Unlock()
	return imageFault{f.closes(session), p.state.LastError, p.state.BanScore}
}

func (f *imageTestFixture) faults() []imageFault {
	faults := make([]imageFault, len(f.peers))
	for i := range faults {
		faults[i] = f.fault(i)
	}
	return faults
}

func (f *imageTestFixture) requireFault(t *testing.T, session, closes int, lastError, label string) {
	t.Helper()
	got, want := f.fault(session), imageFault{closes, lastError, 0}
	require(t, got == want, "%s: fault %+v, want %+v", label, got, want)
}

func (f *imageTestFixture) requireFaultsKept(t *testing.T, want []imageFault, label string) {
	t.Helper()
	got := f.faults()
	require(t, slices.Equal(got, want), "%s: session faults %+v, want %+v", label, got, want)
}

func (f *imageTestFixture) owners(round *ImageRound, session int) imageOwners {
	req := f.lockRequester()
	defer req.mu.Unlock()
	owners := imageOwners{current: len(req.current), idKeys: len(req.lastID)}
	for _, id := range req.lastID {
		owners.ids += id
	}
	if round != nil {
		usage, peerKey := round.perPeer[f.peers[session]]
		owners.perPeer, owners.peerKey = *cmp.Or(usage, &imageUnitVector{}), peerKey
		owners.global, owners.attempted, owners.starts, owners.peerKeys = round.global, len(round.attempted), len(round.starts), len(round.perPeer)
	}
	return owners
}

func (f *imageTestFixture) requireOwners(t *testing.T, round *ImageRound, session int, want imageOwners, label string) {
	t.Helper()
	got := f.owners(round, session)
	require(t, got == want, "%s: owner state %+v, want %+v", label, got, want)
}

func (f *imageTestFixture) snapshot(round *ImageRound, session int) imageSnapshot {
	return imageSnapshot{f.owners(round, session), f.fault(session), len(f.wires[session].bytes())}
}

// imageDrop is the current assignments a refused request's pass releases: on its session, in its round, in the Service.
type imageDrop struct {
	perPeer, global uint64
	current         int
}

func (f *imageTestFixture) refusedAfterPass(t *testing.T, round *ImageRound, session int, start byte, want error, drop imageDrop) {
	t.Helper()
	f.refusedDropping(t, round, context.Background(), f.ids[session], session, start, imageTestByteLimit, want, drop)
}

func (f *imageTestFixture) refusedDropping(t *testing.T, round *ImageRound, ctx context.Context, sourceID string, session int, start byte, byteLimit uint32, want error, drop imageDrop) {
	t.Helper()
	wantAfter, faults := f.snapshot(round, session), f.faults()
	got := requestWithin(lifecycleWatchdog, round, ctx, sourceID, start, byteLimit)
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, want, fmt.Sprintf("start %d", start))
	wantAfter.current -= drop.current
	wantAfter.perPeer[unitCurrentAssignments] -= drop.perPeer
	wantAfter.global[unitCurrentAssignments] -= drop.global
	after := f.snapshot(round, session)
	require(t, after == wantAfter, "start %d: state after the refusal %+v, want %+v", start, after, wantAfter)
	f.requireFaultsKept(t, faults, fmt.Sprintf("start %d", start))
}

func (f *imageTestFixture) refused(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte, want error) {
	t.Helper()
	f.refusedDropping(t, round, ctx, f.ids[session], session, start, imageTestByteLimit, want, imageDrop{})
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
	owners := f.owners(round, session)
	return owners.perPeer, owners.global
}

func imageUsage(current, starts, attempts, admitted, pending uint64) imageUnitVector {
	return ImageUnits{CurrentAssignments: current, DistinctStarts: starts, SourceAttempts: attempts, AdmittedRequests: admitted, PendingNetworkBytes: pending}.vector()
}

func (f *imageTestFixture) requireUsage(t *testing.T, round *ImageRound, session int, perPeer, global imageUnitVector, label string) {
	t.Helper()
	gotPerPeer, gotGlobal := f.usage(round, session)
	require(t, gotPerPeer == perPeer && gotGlobal == global, "%s: usage per peer %v global %v, want %v %v", label, gotPerPeer, gotGlobal, perPeer, global)
}

func (f *imageTestFixture) instance(start byte) *imageInstance {
	req := f.lockRequester()
	defer req.mu.Unlock()
	return currentLocked(req, imageTestAnchor, start)
}

func currentLocked(req *imageRequester, anchor ImageAnchor, start byte) *imageInstance {
	for _, inst := range req.current {
		if inst.round.anchor == anchor && inst.query.StartKey == imageStart(start) {
			return inst
		}
	}
	return nil
}

func (f *imageTestFixture) ended(inst *imageInstance) (bool, error) {
	require(f.t, inst != nil, "no instance to read")
	req := f.lockRequester()
	defer req.mu.Unlock()
	return inst.retired, inst.end
}

func (f *imageTestFixture) requireEnd(t *testing.T, inst *imageInstance, want error, label string) {
	t.Helper()
	retired, end := f.ended(inst)
	require(t, retired == (want != nil) && end == want, "%s: retired=%v end=%v, want %v", label, retired, end, want) //nolint:errorlint // The recorded end is want itself.
}

func (f *imageTestFixture) waitRetired(t *testing.T, inst *imageInstance, want error, label string) {
	t.Helper()
	synctest.Wait()
	f.requireEnd(t, inst, want, label)
}

func (f *imageTestFixture) waitAdmitted(t *testing.T, session int, id uint64, label string) {
	t.Helper()
	imageSpin(t, func() bool { return f.lastID(session) == id }, fmt.Sprintf("%s: allocation of id %d", label, id))
}

// imageRequestCommand is the 12-byte command field of the request frame (RUBIN_L1_P2P_AUX.md Section 7.1).
var imageRequestCommand = [12]byte{0x67, 0x65, 0x74, 0x75, 0x74, 0x78, 0x6f, 0x69, 0x6d, 0x67, 0x00, 0x00}

func (f *imageTestFixture) frames(t *testing.T, session int) []consensus.UTXOImageQuery {
	t.Helper()
	cfg, reader := f.s.cfg.PeerRuntimeConfig, bytes.NewReader(f.wires[session].bytes())
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

func isImageRequestCommand(command string) bool {
	return len(command) <= len(imageRequestCommand) && [12]byte([]byte(command+string(make([]byte, 12)))) == imageRequestCommand
}

func (f *imageTestFixture) requireFrames(t *testing.T, session int, label string, want ...consensus.UTXOImageQuery) {
	t.Helper()
	got := f.frames(t, session)
	require(t, slices.Equal(got, want), "%s: session %d getutxoimg queries=%+v, want %+v", label, session, got, want)
}

func (f *imageTestFixture) closes(session int) int {
	_, closes := f.conns[session].snapshot()
	return closes
}

func (f *imageTestFixture) holdWrite(t *testing.T, session int) (release func() error) {
	t.Helper()
	stall, done := f.wires[session].armStallAfter(0), make(chan error, 1)
	go func() { done <- f.peers[session].send(messagePing, make([]byte, 8)) }()
	requireChannelClosed(t, stall.entered, "holder write")
	return func() error { t.Helper(); stall.release <- nil; return awaitImageResult(t, done, "holder write") }
}

func (f *imageTestFixture) stalledRequest(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte) (*imageStall, <-chan imageResult) {
	t.Helper()
	stall := f.wires[session].armStallAfter(0)
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
	t.Run("pending request bytes at the uint64 maximum limit pass at equality and refuse one over", testImagePendingAtMaximum)
	t.Run("a release of one holder's pending request bytes keeps another holder's", testImagePendingReleaseSites)
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
	t.Run("round admission before, at and after NotBefore", testImageBackoffGate)
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
	f.waitRetired(t, inst, context.Canceled, "canceled instance")
	f.admitted(t, second, context.Background(), 1, 2, 1)
	f.admitted(t, second, context.Background(), 0, 3, 4)
	f.wires[0].armStallAfter(0).release <- errImageScriptedWrite
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
	f, limits := newImageTestFixture(t, 3), imageTestLimits(50*time.Millisecond)
	first := f.round(t, limits, 0, 1, 2)
	second := f.round(t, limits, 0, 1, 2)
	reads := f.clock.readCount()
	stall, pending := f.stalledRequest(t, first, context.Background(), 0, 0x81)
	f.requireTimerSpent(t, imageTestAnchor, 0x81, reads+3)
	f.refused(t, second, context.Background(), 1, 0x81, errImageAssignmentCurrent)
	f.admitTimerSpent(t, second, context.Background(), 1, 0x82, 1)
	stall.release <- nil
	requireImageResult(t, awaitImageResult(t, pending, "stalled request"), 1, 0x81, nil, "stalled request")
	f.requireFrames(t, 1, "parallel start", expectedImageQuery(1, 0x82))
	var wantOther []consensus.UTXOImageQuery
	for i, change := range []func(*ImageAnchor){
		func(a *ImageAnchor) { a.Height = 8 }, func(a *ImageAnchor) { a.BlockHash[31] = 1 }, func(a *ImageAnchor) { a.Root[31] = 1 },
	} {
		other := imageTestAnchor
		change(&other)
		otherRound, err := f.begin(context.Background(), ImageRoundConfig{Anchor: other, SourceIDs: []string{f.ids[2]}, Limits: limits})
		must(t, err, "BeginImageRound other anchor")
		want := expectedImageQuery(uint64(i+1), 0x81)
		want.Height, want.BlockHash, want.Root = other.Height, other.BlockHash, other.Root
		reads = f.clock.readCount()
		requireQueryResult(t, f.request(otherRound, context.Background(), 2, 0x81), want, nil, fmt.Sprintf("anchor %d with a start current at the test anchor", i))
		f.requireTimerSpent(t, other, 0x81, reads+3)
		wantOther = append(wantOther, want)
	}
	f.requireFrames(t, 2, "other anchors with the same start", wantOther...)
	f.clock.add(50*time.Millisecond + time.Nanosecond)
	f.refusedAfterPass(t, first, 0, 0x81, errImageAttempted, imageDrop{1, 1, 5})
	f.admitted(t, first, context.Background(), 1, 0x81, 2)
}

func testImageOneCurrentRace(t *testing.T) {
	f, round := newImageRound(t, 8, 0, 1, 2, 3, 4, 5, 6, 7)
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
	f.requireFaultsKept(t, make([]imageFault, len(f.ids)), "after the concurrent requests")
	f.requireOwners(t, round, admitted[0], imageOneInstance(1), "after the concurrent requests")
}

func testImageCountLimits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		field    func(*ImageUnits) *uint64
		released bool
	}{
		{"current assignments", func(u *ImageUnits) *uint64 { return &u.CurrentAssignments }, true},
		{"distinct starts", func(u *ImageUnits) *uint64 { return &u.DistinctStarts }, false},
		{"source attempts", func(u *ImageUnits) *uint64 { return &u.SourceAttempts }, false},
		{"admitted requests", func(u *ImageUnits) *uint64 { return &u.AdmittedRequests }, false},
	} {
		for _, global := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s global=%v", tc.name, global), inImageBubble(func(t *testing.T) {
				f, limits := newImageTestFixture(t, 2), imageTestLimits()
				*tc.field(map[bool]*ImageUnits{false: &limits.PerPeer, true: &limits.Global}[global]) = 2
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
				f.waitRetired(t, inst, context.Canceled, "canceled instance")
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

func testImagePendingBytes(t *testing.T) {
	for _, global := range []bool{true, false} {
		for _, limit := range []uint64{240, 239} {
			t.Run(fmt.Sprintf("global=%v limit %d", global, limit), func(t *testing.T) {
				f, session := newImageTestFixture(t, 2), map[bool]int{true: 1}[global]
				limits := imageTestLimits()
				map[bool]*ImageUnits{false: &limits.PerPeer, true: &limits.Global}[global].PendingNetworkBytes = limit
				round := f.round(t, limits, 0, 1)
				stall, held := f.stalledRequest(t, round, context.Background(), 0, 1)
				stall1, id, next := f.wires[1].armStallAfter(0), uint64(3-2*session), (<-chan imageResult)(nil)
				if limit == 239 {
					f.refused(t, round, context.Background(), 0, 2, errImageLimit)
				} else {
					ctx, cancel := context.WithCancel(context.Background())
					ended := f.goRequest(round, ctx, 0, 2)
					f.waitAdmitted(t, 0, 2, "request waiting for writeMu")
					cancel()
					requireImageResult(t, awaitImageResult(t, ended, "ended request"), 2, 2, context.Canceled, "ended request")
					next = f.goRequest(round, context.Background(), session, 3)
					f.waitAdmitted(t, session, id, "request at the limit")
					f.refused(t, round, context.Background(), session, 4, errImageLimit)
				}
				stall.release <- nil
				stall1.release <- nil
				requireImageResult(t, awaitImageResult(t, held, "held request"), 1, 1, nil, "held request")
				if next != nil {
					requireImageResult(t, awaitImageResult(t, next, "request at the limit"), id, 3, nil, "request at the limit")
				}
			})
		}
	}
}

// testImagePendingReleaseSites: A releases 120 bytes while B holds 120 of a 240 limit; C fits (240), D refuses (360).
func testImagePendingReleaseSites(t *testing.T) {
	type site struct {
		name                string
		perPeer, endInWrite bool
		writeResult         error
	}
	for _, tc := range []site{
		{"post-write global", false, false, nil},
		{"post-write per-peer", true, false, nil},
		{"post-write after an end during the write global", false, true, nil},
		{"post-write after an end during the write per-peer", true, true, nil},
		{"failed write global", false, false, net.ErrClosed},
		{"send unwind global", false, false, errImageWritePanic},
		{"send unwind per-peer", true, false, errImageWritePanic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, limits, other := newImageTestFixture(t, 2), imageTestLimits(), 1
			limits.Global.PendingNetworkBytes = 240
			if tc.perPeer {
				limits.PerPeer.PendingNetworkBytes, limits.Global.PendingNetworkBytes, other = 240, 1<<20, 0
			}
			round := f.round(t, limits, 0, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stallA := f.wires[0].armStallAfter(0)
			doneA := f.goRecovered(round, ctx, 0, 1)
			requireChannelClosed(t, stallA.entered, "write of holder A")
			inst := f.instance(1)
			stallB := f.wires[other].armStallAfter(1 - other) // Behind A, skip A's payload write.
			heldB := f.goRequest(round, context.Background(), other, 2)
			idB := map[bool]uint64{true: 2, false: 1}[tc.perPeer]
			f.waitAdmitted(t, other, idB, "holder B")
			if tc.endInWrite {
				cancel()
				imageSpin(t, func() bool { retired, _ := f.ended(inst); return retired }, "end during the write")
			}
			stallA.release <- tc.writeResult
			wantA := map[bool]any{false: imageResult{expectedImageQuery(1, 1), tc.writeResult}, true: imageUnwindSentinel}[errors.Is(tc.writeResult, errImageWritePanic)]
			requireEqual(t, awaitImageResult(t, doneA, "holder A"), wantA, "holder A result or recovered value")
			requireChannelClosed(t, stallB.entered, "write of holder B")
			nextC := f.goRequest(round, context.Background(), other, 3)
			f.waitAdmitted(t, other, idB+1, "request C")
			f.refused(t, round, context.Background(), other, 4, errImageLimit)
			perPeer, global := f.usage(round, other)
			require(t, perPeer[unitPendingNetworkBytes] == 240 && global[unitPendingNetworkBytes] == 240,
				"pending bytes per peer %d global %d, want 240 and 240", perPeer[unitPendingNetworkBytes], global[unitPendingNetworkBytes])
			stallB.release <- nil
			requireImageResult(t, awaitImageResult(t, heldB, "holder B"), idB, 2, nil, "holder B")
			requireImageResult(t, awaitImageResult(t, nextC, "request C"), idB+1, 3, nil, "request C")
		})
	}
}

func testImagePendingAtMaximum(t *testing.T) {
	for _, global := range []bool{false, true} {
		f, limits := newImageTestFixture(t, 1), imageTestLimits()
		map[bool]*ImageUnits{false: &limits.PerPeer, true: &limits.Global}[global].PendingNetworkBytes = math.MaxUint64
		round := f.round(t, limits, 0)
		round.perPeer[f.peers[0]] = &imageUnitVector{}
		used := map[bool]*imageUnitVector{false: round.perPeer[f.peers[0]], true: &round.global}[global]
		used[unitPendingNetworkBytes] = math.MaxUint64 - 119
		f.refused(t, round, context.Background(), 0, 1, errImageLimit)
		used[unitPendingNetworkBytes] = math.MaxUint64 - 120
		f.admitted(t, round, context.Background(), 0, 1, 1)
	}
}

func testImageDistinctStarts(t *testing.T) {
	f, limits := newImageTestFixture(t, 2), imageTestLimits()
	limits.Global.DistinctStarts, limits.AttemptLifetime = 1, 50*time.Millisecond
	round := f.round(t, limits, 0, 1)
	f.admitTimerSpent(t, round, context.Background(), 0, 0x81, 1)
	f.clock.add(50*time.Millisecond + time.Nanosecond)
	f.admitTimerSpent(t, round, context.Background(), 1, 0x81, 1)
	f.requireUsage(t, round, 1, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "the start admitted again on the second session")
	f.clock.add(50*time.Millisecond + time.Nanosecond)
	f.refusedAfterPass(t, round, 0, 0x82, errImageLimit, imageDrop{0, 1, 1})
	f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 2, 2, 0), "after the refusal")
}

func testImagePerRoundUsage(t *testing.T) {
	t.Run("another round's usage does not count", func(t *testing.T) {
		f, limits := newImageTestFixture(t, 1), imageTestLimits()
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
		f, limits := newImageTestFixture(t, 1), imageTestLimits(time.Second+50*time.Millisecond)
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
		f, limits := newImageTestFixture(t, 2), imageTestLimits()
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
		f.waitRetired(t, inst, context.Canceled, "canceled instance")
		f.admitted(t, r1, context.Background(), 1, 1, 1)
		f.refused(t, r2, context.Background(), 0, 3, errImageLimit)
		called := *r1
		f.clock.onNextRead(func(now time.Time) time.Time { called = *r2; return now })
		reassigned := f.admitted(t, &called, context.Background(), 1, 4, 2)
		require(t, reassigned != nil && reassigned.round.imageRoundUsage == r1.imageRoundUsage && reassigned.deadline.Equal(f.clock.add(0).Add(10*time.Second)), "instance of the request whose round variable was reassigned at its admission clock read: not in the called round with D 10 s after now")
		f.requireFrames(t, 1, "admitting round", expectedImageQuery(1, 1), expectedImageQuery(2, 4))
		require(t, f.instance(1) != inst, "canceled instance still registered")
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
	second := f.admitted(t, round, context.Background(), 1, 1, 1)
	require(t, second.deadline.Equal(t0.Add(20*time.Second+time.Nanosecond)) && first.deadline.Equal(t0.Add(10*time.Second)), "reassigned D=%v first D=%v", second.deadline, first.deadline)
	f.wires[4].armStallAfter(0).release <- errImageScriptedWrite
	requireImageResult(t, f.request(round, context.Background(), 4, 5), 1, 5, errImageScriptedWrite, "failed write")
	f.requireFault(t, 4, 1, errImageScriptedWrite.Error(), "after the failed write")
	f.requireUsage(t, round, 4, imageUsage(0, 1, 1, 1, 0), imageUsage(1, 2, 3, 3, 0), "after the failed write")
	ctx, cancel := context.WithCancel(context.Background())
	ended := f.admitted(t, round, ctx, 3, 6, 1)
	cancel()
	f.waitRetired(t, ended, context.Canceled, "canceled instance")
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
			t0, round := f.clock.Now(), f.round(t, imageTestLimits(), 0)
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

type imageEndCase struct {
	name               string
	lifetime           time.Duration
	apply              func(f *imageTestFixture, t0 time.Time, cancelRequest, cancelRound func())
	want               error
	notWant            []error
	newRound, callback bool
}

func testImageEndBeforeWrite(t *testing.T) {
	for _, tc := range []imageEndCase{
		{name: "request ctx canceled", lifetime: 50 * time.Millisecond, apply: func(f *imageTestFixture, _ time.Time, cancelRequest, _ func()) { f.clock.cancelOnRead(cancelRequest) }, want: errImageRequestEnd, callback: true},
		{name: "request ctx and round ctx canceled at one read", lifetime: 50 * time.Millisecond, apply: func(f *imageTestFixture, _ time.Time, cancelRequest, cancelRound func()) {
			f.clock.cancelOnRead(func() { cancelRequest(); cancelRound() })
		}, want: errImageRequestEnd, newRound: true, callback: true},
		{name: "now after D", apply: func(f *imageTestFixture, t0 time.Time, _, _ func()) {
			f.clock.set(t0.Add(10*time.Second + time.Nanosecond))
		}, want: errImageExpired, notWant: []error{errImageNilContext, errImagePolicy, errImageSourceSet, errImageUnknownSource, errImageRoundDeadline, errImageAssignmentCurrent, errImageAttempted, errImageLimit, errImageIDExhausted, errImageRequestDomain, errServiceClosed, context.Canceled, context.DeadlineExceeded, os.ErrDeadlineExceeded}},
		{name: "now at RD with D equal to RD", lifetime: time.Hour, apply: func(f *imageTestFixture, t0 time.Time, _, _ func()) { f.clock.set(t0.Add(time.Hour)) }, want: errImageRoundDeadline, notWant: []error{errImageExpired}, newRound: true},
		{name: "round ctx canceled", lifetime: 50 * time.Millisecond, apply: func(f *imageTestFixture, _ time.Time, _, cancelRound func()) { f.clock.cancelOnRead(cancelRound) }, want: errImageRoundEnd, newRound: true, callback: true},
		{name: "round ctx canceled at the read that moves now after D", lifetime: 50 * time.Millisecond, apply: func(f *imageTestFixture, t0 time.Time, _, cancelRound func()) {
			f.clock.jumpOnRead(t0.Add(50*time.Millisecond+time.Nanosecond), cancelRound)
		}, want: errImageRoundEnd, newRound: true, callback: true},
		{name: "now at RD with D before RD", apply: func(f *imageTestFixture, t0 time.Time, _, _ func()) { f.clock.set(t0.Add(time.Hour)) }, want: errImageExpired, notWant: []error{errImageRoundDeadline}, newRound: true},
		{name: "request ctx canceled at the read that moves now after D", lifetime: 50 * time.Millisecond, apply: func(f *imageTestFixture, t0 time.Time, cancelRequest, _ func()) {
			f.clock.jumpOnRead(t0.Add(50*time.Millisecond+time.Nanosecond), cancelRequest)
		}, want: errImageRequestEnd, callback: true},
	} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0, limits := f.clock.Now(), imageTestLimits(cmp.Or(tc.lifetime, 10*time.Second))
			roundCtx, cancelRound := newImageEndCtx(t, errImageRoundEnd)
			round := f.roundCtx(t, roundCtx, limits, 0, 1)
			ctx, cancel := newImageEndCtx(t, errImageRequestEnd)
			release := f.holdWrite(t, 0)
			var timerRead <-chan struct{}
			if tc.callback {
				timerRead = f.clock.readFrom("p2p.applyImageEnd")
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
		f, limits := newImageTestFixture(t, 1), imageTestLimits(50*time.Millisecond)
		round := f.round(t, limits, 0)
		ctx, cancel := context.WithCancel(context.Background())
		release := f.holdWrite(t, 0)
		// No ctx is done before the cancel, so the first clock read inside applyImageEnd is the deadline timer's; the
		// cancel runs inside a clock read of the parked request's endBeforeWrite, which holds the requester mutex.
		timerRead := f.clock.readFrom("p2p.applyImageEnd")
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
	t0, round := f.clock.Now(), f.round(t, imageTestLimits(), 0)
	session := f.peers[0]
	// Reads with writeMu free leave the clock; the first read with writeMu held moves now past D.
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

func testImageRecordedEndKept(t *testing.T) {
	for _, tc := range []struct {
		name            string
		round, callback bool
		want            error
	}{{"request ctx", false, false, errImageExpired}, {"round ctx", true, false, errImageExpired}, {"request ctx after the round ctx callback", false, true, errImageRoundEnd}} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0 := f.clock.Now()
			roundCtx, cancelRound := newImageEndCtx(t, errImageRoundEnd)
			ctx, cancel := newImageEndCtx(t, errImageRequestEnd)
			end := map[bool]func(){false: cancel, true: cancelRound}[tc.round]
			parked := f.roundCtx(t, roundCtx, imageTestLimits(), 0)
			other := f.round(t, imageTestLimits(), 1)
			release := f.holdWrite(t, 0)
			pending := f.goRequest(parked, ctx, 0, 1)
			f.waitAdmitted(t, 0, 1, "parked request")
			inst := f.instance(1)
			if tc.callback {
				synctest.Wait()
				cancelRound()
				f.waitRetired(t, inst, errImageRoundEnd, "round ctx callback")
				f.clock.onReadFrom(".(*ImageRound).endBeforeWrite", func(now time.Time) time.Time { cancel(); return now })
			} else {
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
			}
			requireImageResult(t, awaitImageResult(t, pending, "parked request"), 1, 1, tc.want, "parked request")
			requireEqual(t, f.closes(0), 0, "session closes after the recorded end")
			f.waitRetired(t, inst, tc.want, "after the parked request returned")
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

func testImageDoneAtAdmissionRead(t *testing.T) {
	endCtx := func() (context.Context, context.CancelFunc) { return newImageEndCtx(t, errImageRequestEnd) }
	cancelCtx := func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }
	for _, tc := range []struct {
		name, ends string
		requestCtx func() (context.Context, context.CancelFunc)
		want       error
	}{
		{"request ctx", "request", endCtx, errImageRequestEnd},
		{"request ctx from context.WithCancel", "request", cancelCtx, context.Canceled},
		{"round ctx", "round", endCtx, errImageRoundEnd},
		{"request ctx and round ctx", "both", endCtx, errImageRequestEnd},
	} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			roundCtx, cancelRound := newImageEndCtx(t, errImageRoundEnd)
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
			f.requireEnd(t, first, nil, "first instance after the refusal")
			f.requireUsage(t, firstRound, 0, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 1, 1, 0), "first instance's round after the refusal")
			next := round
			if tc.ends != "request" {
				next = f.round(t, imageTestLimits(), 0, 1)
			}
			f.admitted(t, next, context.Background(), 1, 1, 1)
			f.requireEnd(t, first, errImageExpired, "first instance after the next request")
		}))
	}
}

func testImageRequestRetiresEnded(t *testing.T) {
	t.Run("same round", inImageBubble(func(t *testing.T) {
		f, limits := newImageTestFixture(t, 2), imageTestLimits(50*time.Millisecond)
		round := f.round(t, limits, 0, 1)
		ctx, cancel := context.WithCancel(context.Background())
		inst := f.admitTimerSpent(t, round, ctx, 0, 0x81, 1)
		f.clock.set(inst.deadline)
		f.refused(t, round, context.Background(), 0, 0x81, errImageAssignmentCurrent)
		f.clock.set(inst.deadline.Add(time.Nanosecond))
		f.refusedAfterPass(t, round, 0, 0x81, errImageAttempted, imageDrop{1, 1, 1})
		f.requireEnd(t, inst, errImageExpired, "pass")
		f.admitted(t, round, context.Background(), 0, 0x82, 2)
		f.admitted(t, round, context.Background(), 1, 0x81, 1)
		cancel()
		synctest.Wait()
		f.requireEnd(t, inst, errImageExpired, "after cancellation")
		f.refused(t, round, context.Background(), 0, 0x81, errImageAssignmentCurrent)
		replacement := f.instance(0x81)
		require(t, replacement != nil && replacement.session == f.peers[1], "replacement not current")
		f.admitted(t, round, context.Background(), 0, 0x83, 3)
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

func newImageEndCtx(t *testing.T, err error) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return imageEndCtx{ctx, err}, cancel
}

func testImagePassEndOrder(t *testing.T) {
	for _, tc := range []struct {
		name           string
		request, round bool
		after          time.Duration
		want           error
	}{
		{"request ctx done with now short of D", true, false, 0, errImageRequestEnd},
		{"round ctx done with now short of D", false, true, 0, errImageRoundEnd},
		{"request ctx done with now after D", true, false, 10*time.Second + time.Nanosecond, errImageRequestEnd},
		{"round ctx done with now after D", false, true, 10*time.Second + time.Nanosecond, errImageRoundEnd},
		{"request ctx and round ctx done with now after D", true, true, 10*time.Second + time.Nanosecond, errImageRequestEnd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixture(t, 2)
			t0 := f.clock.Now()
			roundCtx, cancelRound := newImageEndCtx(t, errImageRoundEnd)
			ctx, cancel := newImageEndCtx(t, errImageRequestEnd)
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
			f.requireEnd(t, inst, tc.want, "pass")
			want := before
			want[unitCurrentAssignments]--
			f.requireUsage(t, ended, 0, want, want, "pass usage of the single-source round")
			requireEqual(t, f.lastID(0), uint64(1), "session 0 last id")
		})
	}
}

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
	f.clock.set(t0.Add(24*time.Hour + time.Nanosecond))
	for i, tc := range []struct {
		round     *ImageRound
		ctx       context.Context
		session   int
		byteLimit uint32
		want      error
	}{
		{round, imageNilCtx, 0, imageTestByteLimit, errImageNilContext},
		{round, canceled, 0, imageTestByteLimit, context.Canceled},
		{doneRound, context.Background(), 0, imageTestByteLimit, context.Canceled},
		{round, context.Background(), 1, imageTestByteLimit, errImageUnknownSource},
		{round, context.Background(), 0, 150904, errImageRequestDomain},
	} {
		f.refusedDropping(t, tc.round, tc.ctx, f.ids[tc.session], tc.session, 2, tc.byteLimit, tc.want, imageDrop{})
		f.requireEnd(t, inst, nil, fmt.Sprintf("refusal %d before the pass", i))
	}
	f.admitted(t, round, context.Background(), 0, 2, 2)
	f.requireEnd(t, inst, errImageExpired, "pass")
}

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

func testImageRefusalKeepsPass(t *testing.T) {
	for _, tc := range []imagePassRefusal{
		{"now at the round deadline", errImageRoundDeadline, imageDrop{1, 1, 1}, func(_ *testing.T, f *imageTestFixture, ended *ImageRound, t0 time.Time) (*ImageRound, int, byte) {
			f.clock.set(t0.Add(time.Hour))
			return ended, 0, 2
		}},
		{"attempt deadline not representable", errImagePolicy, imageDrop{0, 0, 1}, func(t *testing.T, f *imageTestFixture, _ *ImageRound, _ time.Time) (*ImageRound, int, byte) {
			return f.round(t, imageTestLimits(math.MaxInt64), 0), 0, 2
		}},
		{"current assignment of the start", errImageAssignmentCurrent, imageDrop{0, 0, 1}, func(t *testing.T, f *imageTestFixture, _ *ImageRound, _ time.Time) (*ImageRound, int, byte) {
			holder := f.round(t, imageTestLimits(), 1)
			f.admitted(t, holder, context.Background(), 1, 2, 1)
			return holder, 1, 2
		}},
		{"start attempted on the session", errImageAttempted, imageDrop{1, 1, 1}, func(_ *testing.T, _ *imageTestFixture, ended *ImageRound, _ time.Time) (*ImageRound, int, byte) {
			return ended, 0, 1
		}},
		{"source attempts limit", errImageLimit, imageDrop{1, 1, 1}, func(_ *testing.T, _ *imageTestFixture, ended *ImageRound, _ time.Time) (*ImageRound, int, byte) {
			return ended, 0, 2
		}},
		{"request id space exhausted", errImageIDExhausted, imageDrop{0, 1, 1}, func(_ *testing.T, f *imageTestFixture, ended *ImageRound, _ time.Time) (*ImageRound, int, byte) {
			f.setLastID(1, 18446744073709551615)
			return ended, 1, 2
		}},
	} {
		start := time.Now()
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixtureAt(t, 2, start)
			t0, limits := f.clock.Now(), imageTestLimits(50*time.Millisecond)
			limits.PerPeer.SourceAttempts = 1
			ended := f.round(t, limits, 0, 1)
			inst := f.admitTimerSpent(t, ended, context.Background(), 0, 1, 1)
			perPeerBefore, globalBefore := f.usage(ended, 0)
			round, session, start := tc.prepare(t, f, ended, t0)
			if past := t0.Add(50*time.Millisecond + time.Nanosecond); f.clock.add(0).Before(past) {
				f.clock.set(past)
			}
			f.refusedAfterPass(t, round, session, start, tc.want, tc.drop)
			f.requireEnd(t, inst, errImageExpired, "after the refusal")
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
			f.waitRetired(t, inst, wantEnd, "end during the write")
			f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 120), globalDuring, "during the write")
			f.refused(t, round, context.Background(), 0, 2, errImageLimit)
			if !tc.pass {
				f.admitted(t, round, context.Background(), 1, 1, 1)
			}
			stall.release <- tc.writeErr
			requireImageResult(t, awaitImageResult(t, pending, "written request"), 1, 1, nil, "after the write")
			f.requireEnd(t, inst, wantEnd, "after the write")
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
		f.waitRetired(t, inst, context.Canceled, "round ctx end")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 120), imageUsage(0, 1, 1, 1, 120), "during the write")
		stall.release <- nil
		requireImageResult(t, awaitImageResult(t, pending, "written request"), 1, 1, nil, "after the write")
		f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "after the write")
		f.requireFrames(t, 0, "round ctx end", expectedImageQuery(1, 1))
	}))
}

func testImageFrameWriteDeadline(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		roundLifetime, ctxTimeout time.Duration
	}{
		{"attempt lifetime 1 s", time.Hour, 0}, {"attempt lifetime 1 s, round lifetime 2 s and ctx deadlines in 10 s", 2 * time.Second, 10 * time.Second},
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
			f.waitRetired(t, inst, context.Canceled, name)
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
		f.requireEnd(t, inst, context.Canceled, "end recorded by the callback before Close returned")
	})
	t.Run("a ctx callback or the deadline timer triggered after retirement does not run", testImageRetirementStops)
	t.Run("deadline timer with the round ctx done before its callback runs", testImageTimerShortOfD)
}

func testImageTimerShortOfD(t *testing.T) {
	for _, past := range []time.Duration{-1, 0, 1} {
		t.Run(map[time.Duration]string{-1: "now short of D", 0: "now at D", 1: "now past D"}[past], inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			roundCtx := newImageHookCtx()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inst := f.admitted(t, f.roundCtx(t, roundCtx, imageTestLimits(100*time.Millisecond), 0), ctx, 0, 1, 1)
			if past >= 0 {
				f.clock.set(inst.deadline.Add(past))
			}
			roundCtx.end(errImageRoundEnd)
			reads := f.clock.readCount()
			time.Sleep(time.Second)
			synctest.Wait()
			req := f.lockRequester()
			retired, end, rearmed := inst.retired, inst.end, inst.timer.Stop()
			req.mu.Unlock()
			requireEqual(t, f.clock.readCount(), reads+1, "clock reads by the deadline timer")
			want := map[bool]error{true: errImageRoundEnd}[past > 0]
			require(t, retired == (want != nil) && end == want && !rearmed, "deadline timer with the round ctx done: retired=%v end=%v armed again=%v, want end %v", retired, end, rearmed, want) //nolint:errorlint // The recorded end is want itself.
			cancel()
			f.waitRetired(t, inst, cmp.Or(want, context.Canceled), "request ctx callback")
		}))
	}
}

// imageHookCtx is a Context that is live until end. onAfterFunc and onStop replace the first AfterFunc and stop;
// onSecondErr runs inside the second Err call.
type imageHookCtx struct {
	mu                               sync.Mutex
	once                             sync.Once
	done                             chan struct{}
	err                              error
	errCalls, applierErrs            int
	funcs                            map[*func()]struct{}
	onAfterFunc, onStop, onSecondErr func()
}

func newImageHookCtx() *imageHookCtx {
	return &imageHookCtx{done: make(chan struct{}), funcs: make(map[*func()]struct{})}
}
func (c *imageHookCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *imageHookCtx) Done() <-chan struct{}       { return c.done }
func (c *imageHookCtx) Value(any) any               { return nil }
func (c *imageHookCtx) Err() error {
	c.mu.Lock()
	c.errCalls++
	if imageCalledFrom("p2p.applyImageEnd") {
		c.applierErrs++
	}
	err, hold := c.err, c.errCalls == 2 && c.onSecondErr != nil
	c.mu.Unlock()
	if hold {
		c.onSecondErr()
	}
	return err
}
func (c *imageHookCtx) end(err error) { c.mu.Lock(); c.err = err; c.once.Do(c.shut); c.mu.Unlock() }
func (c *imageHookCtx) shut()         { close(c.done) }
func (c *imageHookCtx) endAndRun(err error) int {
	c.end(err)
	c.mu.Lock()
	funcs := slices.Collect(maps.Keys(c.funcs))
	c.mu.Unlock()
	for _, f := range funcs {
		(*f)()
	}
	return len(funcs)
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

type imageBubble struct {
	f                          *imageTestFixture
	round                      *ImageRound
	inst                       *imageInstance
	t0                         time.Time
	cancelRequest, cancelRound context.CancelFunc
}

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
		body(t, imageBubble{f, round, f.admitted(t, round, ctx, 0, 1, 1), t0, cancel, cancelRound})
	})(t)
}

func (b imageBubble) expire() {
	b.f.clock.set(b.t0.Add(100*time.Millisecond + time.Nanosecond))
	b.passTimer()
}
func (b imageBubble) passTimer() { time.Sleep(time.Second); synctest.Wait() }
func (b imageBubble) state() (bool, int, time.Time, imageOwners, error) {
	retired, end := b.f.ended(b.inst)
	owners := b.f.owners(b.round, 0)
	b.f.clock.mu.Lock()
	defer b.f.clock.mu.Unlock()
	return retired, b.f.clock.reads, b.f.clock.now, owners, end
}

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

func testImageCallbackOrTimerAfterClose(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger func(b imageBubble)
		stop    func(inst *imageInstance) bool
	}{
		{"request ctx callback", imageBubble.endRequest, func(inst *imageInstance) bool { return inst.stopCtx() }}, {"round ctx callback", imageBubble.endRound, func(inst *imageInstance) bool { return inst.stopRound() }}, {"deadline timer", imageBubble.passTimer, func(inst *imageInstance) bool { return inst.timer.Stop() }},
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

func testImageRetirementStops(t *testing.T) {
	for _, tc := range []struct {
		name          string
		retire, later func(b imageBubble)
		end           error
	}{
		{"deadline timer after a request ctx end", imageBubble.endRequest, imageBubble.expire, context.Canceled},
		{"round ctx callback after a request ctx end", imageBubble.endRequest, imageBubble.endRound, context.Canceled},
		{"request ctx callback after a round ctx end", imageBubble.endRound, imageBubble.endRequest, context.Canceled},
		{"request ctx callback after a deadline", imageBubble.expire, imageBubble.endRequest, errImageExpired},
		{"round ctx callback after a deadline", imageBubble.expire, imageBubble.endRound, errImageExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runImageBubble(t, false, func(t *testing.T, b imageBubble) {
				tc.retire(b)
				retired, reads, _, owners, end := b.state()
				armed, ctxArmed, roundArmed := b.inst.timer.Stop(), b.inst.stopCtx(), b.inst.stopRound()
				require(t, retired && end == tc.end && owners == imageOneInstance(0) && !armed && !ctxArmed && !roundArmed, "first end: retired=%v end=%v owner state %+v timer, request ctx and round ctx armed=%v %v %v, want retired with %v and the three stopped", retired, end, owners, armed, ctxArmed, roundArmed, tc.end) //nolint:errorlint // The recorded end is the first end's ctx error itself.
				tc.later(b)
				_, after, _, _, end := b.state()
				require(t, after == reads && end == tc.end, "callback or timer after retirement: clock reads %d->%d end %v, want no read and the end %v kept", reads, after, end, tc.end) //nolint:errorlint // The kept end is the first end's ctx error itself.
			})
		})
	}
}
func (b imageBubble) endRequest() { b.cancelRequest(); synctest.Wait() }
func (b imageBubble) endRound()   { b.cancelRound(); synctest.Wait() }
func testImageSaturatedTimer(t *testing.T) {
	f := newImageTestFixture(t, 1)
	t0, limits := f.clock.Now(), imageTestLimits(math.MaxInt64, math.MaxInt64)
	inst := f.admitted(t, f.round(t, limits, 0), context.Background(), 0, 1, 1)
	require(t, inst.deadline.Sub(t0) == math.MaxInt64, "D-now=%v, want the largest Duration", inst.deadline.Sub(t0))
	require(t, imageTimerDuration(math.MaxInt64) == math.MaxInt64 && imageTimerDuration(math.MaxInt64-1) == math.MaxInt64 && imageTimerDuration(0) == 1, "timer durations for D-now of the largest Duration, one less and 0: %v %v %v, want the largest Duration twice and 1ns", imageTimerDuration(math.MaxInt64), imageTimerDuration(math.MaxInt64-1), imageTimerDuration(0))
	// A timer duration past the runtime's largest instant fires at that instant.
	reads := f.clock.readCount()
	time.Sleep(time.Duration(math.MaxInt64 - time.Now().UnixNano() - 1))
	synctest.Wait()
	req := f.lockRequester()
	armed := inst.timer.Stop()
	req.mu.Unlock()
	retired, _ := f.ended(inst)
	require(t, armed && !retired && f.instance(1) == inst && f.clock.readCount() == reads, "one tick before the largest instant: timer armed=%v retired=%v clock reads %d->%d, want armed, current and no read", armed, retired, reads, f.clock.readCount())
}

func (f *imageTestFixture) admitTimerSpent(t *testing.T, round *ImageRound, ctx context.Context, session int, start byte, wantID uint64) *imageInstance {
	t.Helper()
	reads := f.clock.readCount()
	f.admitted(t, round, ctx, session, start, wantID)
	return f.requireTimerSpent(t, imageTestAnchor, start, reads+3)
}

func (f *imageTestFixture) requireTimerSpent(t *testing.T, anchor ImageAnchor, start byte, reads int) *imageInstance {
	t.Helper()
	synctest.Wait()
	req := f.lockRequester()
	inst := currentLocked(req, anchor, start)
	req.mu.Unlock()
	if inst != nil && f.clock.readCount() < reads {
		time.Sleep(inst.deadline.Sub(f.clock.add(0)) + time.Nanosecond)
		synctest.Wait()
	}
	req = f.lockRequester()
	retired, rearmed := inst == nil || currentLocked(req, anchor, start) != inst, false
	if inst != nil {
		retired, rearmed = retired || inst.retired, inst.timer.Stop()
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
		f, round := newImageRound(t, 2, 0, 1)
		var inHook imageResult
		// The hook runs inside the failed request, whose own bound is lifecycleWatchdog.
		f.onClose(0, func() {
			inHook = requestWithin(lifecycleWatchdog/2, round, context.Background(), f.ids[1], 1, imageTestByteLimit)
		})
		stall := f.wires[0].armStallAfter(0)
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
	for skip := range 2 {
		t.Run(fmt.Sprintf("a request on the same session in the close hook of a write failed after %d header bytes", skip*wireHeaderSize), func(t *testing.T) {
			f, round := newImageRound(t, 1, 0)
			inHook := imageResult{err: errImageNoResult}
			// The hook runs inside the failed request, whose own bound is lifecycleWatchdog.
			f.onClose(0, func() {
				inHook = requestWithin(lifecycleWatchdog/2, round, context.Background(), f.ids[0], 2, imageTestByteLimit)
			})
			// The first stop call of the failed write's retirement, in its post-write section, reads whether writeMu is free.
			c, free := newImageHookCtx(), false
			c.onStop = func() {
				if free = f.peers[0].writeMu.TryLock(); free {
					f.peers[0].writeMu.Unlock()
				}
			}
			f.wires[0].armStallAfter(skip).release <- errImageScriptedWrite
			requireImageResult(t, f.request(round, c, 0, 1), 1, 1, errImageScriptedWrite, "failed write")
			require(t, free, "writeMu held in the post-write section of the failed write")
			requireImageResult(t, inHook, 2, 2, nil, "request on the same session in the close hook")
			f.wires[0].drop(skip * wireHeaderSize)
			f.requireFrames(t, 0, "after the close hook", expectedImageQuery(2, 2))
			f.requireFault(t, 0, 1, errImageScriptedWrite.Error(), "after the failed write")
		})
	}
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
	for _, end := range []string{"request ctx", "round ctx", "now after D"} {
		for _, writeErr := range []error{nil, errImageScriptedWrite} {
			t.Run(fmt.Sprintf("a write returning %v with the %s ended during it and no end applied", writeErr, end), func(t *testing.T) {
				f := newImageTestFixture(t, 1)
				t0, c := f.clock.Now(), newImageHookCtx()
				roundC, requestC := imageUnwindCtx(c, context.Background(), end == "round ctx")
				round := f.roundCtx(t, roundC, imageTestLimits(24*time.Hour, 48*time.Hour), 0)
				stall, pending := f.stalledRequest(t, round, requestC, 0, 1)
				inst := f.instance(1)
				if end == "now after D" {
					f.clock.set(t0.Add(24*time.Hour + time.Nanosecond))
				} else {
					c.end(errors.New("ctx ended with its callback not run"))
				}
				stall.release <- writeErr
				requireImageResult(t, awaitImageResult(t, pending, "written request"), 1, 1, writeErr, "write with an end not applied")
				retired, _ := f.ended(inst)
				failed := map[bool]int{false: 0, true: 1}[writeErr != nil]
				require(t, retired == (failed == 1), "instance after the write: retired=%v, want %v", retired, failed == 1)
				f.requireOwners(t, round, 0, imageOneInstance(1-failed), "after the write")
				f.requireFault(t, 0, failed, map[int]string{0: "", 1: errImageScriptedWrite.Error()}[failed], "after the write")
			})
		}
	}
	t.Run("sibling stays current", func(t *testing.T) {
		f, round := newImageRound(t, 2, 0, 1)
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.wires[0].armStallAfter(0).release <- errImageScriptedWrite
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
	t.Run("a ctx callback that loaded its instance before a retirement under the requester mutex", testImageCallbackAfterRetirement)
	t.Run("write failure of an instance ended during the write", func(t *testing.T) {
		f := newImageTestFixture(t, 3)
		t0, round := f.clock.Now(), f.round(t, imageTestLimits(), 0, 1, 2)
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

func testImageCallbackAfterRetirement(t *testing.T) {
	f, roundC, ctx := newImageTestFixture(t, 1), newImageHookCtx(), newImageHookCtx()
	round := f.roundCtx(t, roundC, imageTestLimits(math.MaxInt64, math.MaxInt64), 0)
	inst := f.admitted(t, round, ctx, 0, 1, 1)
	req, ran, leases := f.lockRequester(), make(chan int, 1), f.leases()
	waitImageMutexWaiter(t, &req.mu, func() { go func() { ran <- ctx.endAndRun(context.Canceled) }() })
	req.retireLocked(inst, errImageExpired)
	reads := f.clock.readCount()
	req.mu.Unlock()
	requireEqual(t, awaitImageResult(t, ran, "Request ctx functions"), 1, "Request ctx functions run")
	imageSpin(t, func() bool { return f.leases() == leases }, "Service lease release by the Request ctx callback")
	require(t, f.clock.readCount() == reads && ctx.applierErrs == 0 && roundC.applierErrs == 0, "callback after the retirement: clock reads %d->%d, Request ctx and round ctx Err calls %d and %d, want none", reads, f.clock.readCount(), ctx.applierErrs, roundC.applierErrs)
	f.requireEnd(t, inst, errImageExpired, "instance retired while its callback waited")
	f.requireOwners(t, round, 0, imageOneInstance(0), "after the callback")
	f.requireUsage(t, round, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "after the callback")
}

func waitImageMutexWaiter(t *testing.T, mu *sync.Mutex, start func()) {
	t.Helper()
	// sync.Mutex starts with the internal/sync.Mutex state word: bit 0 locked, waiter count from bit 3.
	state := (*int32)(unsafe.Pointer(mu))
	requireEqual(t, atomic.LoadInt32(state), int32(1), "requester mutex state locked with no waiter")
	start()
	imageSpin(t, func() bool { return atomic.LoadInt32(state)>>3 != 0 }, "Request ctx callback waiting for the requester mutex")
}

func testImageStaleCallback(t *testing.T) {
	f, limits := newImageTestFixture(t, 3), imageTestLimits(math.MaxInt64, math.MaxInt64)
	round, ctx := f.round(t, limits, 0, 1, 2), newImageHookCtx()
	stale := f.admitted(t, round, ctx, 0, 1, 1)
	f.clock.cancelOnRead(func() { requireEqual(t, ctx.endAndRun(context.Canceled), 1, "stale ctx functions") })
	reads := f.clock.readCount()
	f.admitted(t, round, context.Background(), 1, 1, 1)
	synctest.Wait()
	require(t, f.clock.readCount() == reads+2 && ctx.applierErrs == 0, "stale callback: clock reads %d->%d, its ctx Err calls %d, want only the replacement's 2 reads and none", reads, f.clock.readCount(), ctx.applierErrs)
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
	registry, faults := f.owners(nil, 0), f.faults()
	round, err := f.begin(ctx, config)
	require(t, round == nil && err == want, "%s: round=%v err=%v want %v", label, round != nil, err, want) //nolint:errorlint // The refusal is the wanted sentinel itself, not a wrapper.
	f.requireOwners(t, nil, 0, registry, label)
	f.requireFaultsKept(t, faults, label)
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
		reads := f.clock.readCount()
		f.requireRoundRefused(t, ctx, config, tc.want, tc.name)
		requireEqual(t, f.clock.readCount(), reads, tc.name+": clock reads")
	}
	late := newImageTestFixtureAt(t, 1, time.Unix(imageMaxWall, 999999999).Add(-time.Hour))
	unknown := late.config(imageTestLimits(), 0)
	unknown.SourceIDs, unknown.Limits.RoundLifetime = []string{"absent:1"}, 2*time.Hour
	late.requireRoundRefused(t, context.Background(), unknown, errImageSourceSet, "unknown source with an unrepresentable RD")
}

func testImageSourceBound(t *testing.T) {
	f := newImageTestFixture(t, 2)
	config := f.config(imageTestLimits())
	config.SourceIDs = make([]string, 1<<20)
	for i := range config.SourceIDs {
		config.SourceIDs[i] = fmt.Sprintf("absent-%016d:1", i)
	}
	backing, faults := uint64(cap(config.SourceIDs))*uint64(reflect.TypeFor[string]().Size()), f.faults()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	round, err := f.s.BeginImageRound(context.Background(), config)
	runtime.ReadMemStats(&after)
	grown := after.TotalAlloc - before.TotalAlloc
	require(t, round == nil && errors.Is(err, errImageSourceSet) && grown < backing && grown < uint64(len(config.SourceIDs)), "round=%v err=%v allocated %d bytes, want fewer than the %d source ids and the %d-byte backing array", round != nil, err, grown, len(config.SourceIDs), backing)
	f.requireFaultsKept(t, faults, "source refusal")
	buffer, round := func() (weak.Pointer[byte], *ImageRound) {
		large := f.ids[0] + strings.Repeat("x", 64<<20)
		round, err := f.begin(context.Background(), ImageRoundConfig{Anchor: imageTestAnchor, SourceIDs: []string{large[:len(f.ids[0])]}, Limits: imageTestLimits()})
		must(t, err, "BeginImageRound with a source id inside a 64 MiB string")
		return weak.Make(unsafe.StringData(large)), round
	}()
	runtime.GC()
	require(t, buffer.Value() == nil, "the round keeps the 64 MiB buffer of its source id")
	f.admitted(t, round, context.Background(), 0, 1, 1)
}

func testImageSourceDecision(t *testing.T) {
	f, alias := newImageTestFixture(t, 2), "192.0.2.40:9"
	imageSpin(t, f.s.peersMu.TryRLock, "peersMu")
	peers := maps.Clone(f.s.peers)
	f.s.peersMu.RUnlock()
	require(t, len(peers) == 4 && peers[f.ids[0]] == f.peers[0] && peers[alias] == f.peers[0] && peers[f.ids[1]] == f.peers[1], "Service.peers copy %v, want 4 entries naming session 0 under %s and %s and session 1 under %s", peers, f.ids[0], alias, f.ids[1])
	for _, ids := range [][]string{append(slices.Sorted(maps.Keys(peers)), "absent:1"), {f.ids[0], "absent:1"}, {f.ids[0], alias}} {
		sources, err := imageSources(ids, peers)
		require(t, sources == nil && errors.Is(err, errImageSourceSet), "source decision for %q: sources=%v err=%v, want nil and %v", ids, sources, err, errImageSourceSet)
		f.requireRoundRefused(t, context.Background(), ImageRoundConfig{Anchor: imageTestAnchor, SourceIDs: ids, Limits: imageTestLimits()}, errImageSourceSet, fmt.Sprintf("round with %q", ids))
	}
	want := map[string]*peer{f.ids[0]: f.peers[0], f.ids[1]: f.peers[1]}
	sources, err := imageSources([]string{f.ids[0], f.ids[1]}, want)
	require(t, err == nil && maps.Equal(sources, want), "source decision for as many ids as copied entries: sources=%v err=%v, want %v", sources, err, want)
	sources, err = imageSources([]string{f.ids[0], f.ids[1]}, peers)
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
		f, round := newImageRound(t, 2, 0)
		f.refused(t, round, imageNilCtx, 0, 1, errImageNilContext)
		f.refusedDropping(t, round, context.Background(), f.ids[1], 1, 1, imageTestByteLimit, errImageUnknownSource, imageDrop{})
		f.refusedDropping(t, round, context.Background(), "absent:1", 0, 1, imageTestByteLimit, errImageUnknownSource, imageDrop{})
		f.refusedDropping(t, round, context.Background(), f.ids[1], 1, 1, 150904, errImageUnknownSource, imageDrop{})
		for _, limit := range []uint32{0, 150904, 2097153, math.MaxUint32} {
			f.refusedDropping(t, round, context.Background(), f.ids[0], 0, 1, limit, errImageRequestDomain, imageDrop{})
		}
		expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
		defer cancelExpired()
		done := f.roundCtx(t, expired, imageTestLimits(), 0)
		f.refusedDropping(t, done, context.Background(), "absent:1", 0, 1, imageTestByteLimit, context.DeadlineExceeded, imageDrop{})
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
		f.waitRetired(t, inst, context.Canceled, "canceled instance")
		f.refused(t, round, context.Background(), 0, 2, errImageAttempted)
		f.refused(t, round, context.Background(), 0, 3, errImageLimit)
		f.setLastID(1, 18446744073709551615)
		f.refused(t, round, context.Background(), 1, 3, errImageIDExhausted)
		tight := imageTestLimits()
		tight.PerPeer.PendingNetworkBytes = 119
		f.refused(t, f.round(t, tight, 1), context.Background(), 1, 4, errImageLimit)
		f.clock.set(t0.Add(time.Hour))
		f.refusedDropping(t, round, context.Background(), f.ids[0], 0, 5, 2097153, errImageRequestDomain, imageDrop{})
		f.refusedAfterPass(t, round, 0, 5, errImageRoundDeadline, imageDrop{1, 1, 1})
	}))
	t.Run("done contexts refuse before admission", testImageDoneContexts)
	t.Run("a ctx done at the admission clock read refuses ahead of the pass", testImageDoneAtAdmissionRead)
	t.Run("round deadline and attempt deadline", func(t *testing.T) {
		base := time.Now()
		f := newImageTestFixtureAt(t, 2, base)
		holder := f.round(t, imageTestLimits(time.Hour, 2*time.Hour), 0)
		unrepresentable := f.round(t, imageTestLimits(math.MaxInt64, 10*time.Second), 1)
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

// testImageBackoffGate reads T at the first clock read of a round and T+1ns later (RUBIN_L1_P2P_AUX.md Section 6.6).
func testImageBackoffGate(t *testing.T) {
	f := newImageTestFixture(t, 1)
	t0 := f.clock.Now()
	var later func(time.Time) time.Time
	later = func(time.Time) time.Time { f.clock.onRead = later; return t0.Add(1) }
	f.clock.onNextRead(func(now time.Time) time.Time { f.clock.onRead = later; return now })
	config, reads := f.config(imageTestLimits(), 0), f.clock.readCount()
	config.NotBefore = t0.Add(1)
	f.requireRoundRefused(t, context.Background(), config, errImageBackoff, "now 1ns before NotBefore")
	require(t, f.clock.readCount() == reads+1, "clock reads %d, want one", f.clock.readCount()-reads)
	f.clock.onNextRead(nil)
	config.NotBefore = t0
	round, err := f.begin(context.Background(), config)
	must(t, err, "BeginImageRound at NotBefore")
	f.admitted(t, round, context.Background(), 0, 1, 1)
	config.NotBefore = time.Now().Add(time.Until(t0) - time.Hour)
	f.requireRoundRefused(t, context.Background(), config, errImagePolicy, "monotonic NotBefore at a wall-only now")
	requireReturned(t, lifecycleClose(f.s), "Close after the refused round")
	newImageTestFixtureAt(t, 1, time.Time{}.Add(-time.Hour)).round(t, imageTestLimits(), 0)
	mono := newImageTestFixtureAt(t, 1, time.Now())
	now := mono.clock.Now()
	config = mono.config(imageTestLimits(), 0)
	mono.round(t, config.Limits, 0)
	config.NotBefore = now.Add(-1)
	ahead, err := mono.begin(context.Background(), config)
	must(t, err, "BeginImageRound 1ns after a monotonic NotBefore")
	mono.admitted(t, ahead, context.Background(), 0, 1, 1)
	for _, other := range []error{errImageNilContext, errImagePolicy, errImageSourceSet, errImageUnknownSource, errImageRoundDeadline, errImageAssignmentCurrent, errImageAttempted, errImageLimit, errImageIDExhausted, errImageRequestDomain, errImageExpired, errServiceClosed} {
		require(t, errors.Unwrap(errImageBackoff) == nil && !errors.Is(errImageBackoff, other) && !errors.Is(other, errImageBackoff), "errImageBackoff wraps %v or matches %v", errors.Unwrap(errImageBackoff), other)
	}
	for _, notBefore := range []time.Time{now.Add(-time.Hour).Round(0), now.Add(time.Hour).Round(0)} {
		config.NotBefore = notBefore
		mono.requireRoundRefused(t, context.Background(), config, errImagePolicy, "wall-only NotBefore at a monotonic now")
	}
	config.NotBefore, config.Limits.RoundLifetime = now.Add(1), math.MaxInt64
	mono.requireRoundRefused(t, context.Background(), config, errImagePolicy, "inexact RD ahead of NotBefore")
}

func (f *imageTestFixture) serviceEntry(key string) *peer {
	imageSpin(f.t, f.s.peersMu.TryRLock, "peersMu")
	defer f.s.peersMu.RUnlock()
	return f.s.peers[key]
}

func testImageCapturedSourceID(t *testing.T) {
	t.Run("alias of a captured source", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		owner, alias := f.serviceEntry(f.ids[0]), f.serviceEntry("192.0.2.40:9")
		require(t, owner == f.peers[0] && alias == f.peers[0], "logical address names %p and alias names %p, want session %p", owner, alias, f.peers[0])
		round := f.round(t, imageTestLimits(), 0)
		f.refusedDropping(t, round, context.Background(), "192.0.2.40:9", 0, 1, imageTestByteLimit, errImageUnknownSource, imageDrop{})
		requireEqual(t, f.closes(0), 0, "session closes")
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.requireFrames(t, 0, "logical address", expectedImageQuery(1, 1))
		byAlias, err := f.begin(context.Background(), ImageRoundConfig{Anchor: imageTestAnchor, SourceIDs: []string{"192.0.2.40:9"}, Limits: imageTestLimits()})
		must(t, err, "BeginImageRound with the alias")
		requireImageResult(t, requestWithin(lifecycleWatchdog, byAlias, context.Background(), "192.0.2.40:9", 2, imageTestByteLimit), 2, 2, nil, "request by the alias")
		f.requireFrames(t, 0, "alias", expectedImageQuery(1, 1), expectedImageQuery(2, 2))
	})
	t.Run("caller's source list overwritten after the round began", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		config := f.config(imageTestLimits(), 0)
		round, err := f.begin(context.Background(), config)
		must(t, err, "BeginImageRound")
		config.SourceIDs[0] = "renamed:1"
		f.admitted(t, round, context.Background(), 0, 1, 1)
		f.requireFrames(t, 0, "original source id", expectedImageQuery(1, 1))
		f.refusedDropping(t, round, context.Background(), "renamed:1", 0, 2, imageTestByteLimit, errImageUnknownSource, imageDrop{})
	})
	t.Run("newer registration of the logical address", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		owner := f.serviceEntry(f.ids[0])
		require(t, owner == f.peers[0], "logical address names %p at round construction, want session %p", owner, f.peers[0])
		round := f.round(t, imageTestLimits(), 0)
		newer := f.addSession(t, f.ids[0], "192.0.2.81:9")
		owner = f.serviceEntry(f.ids[0])
		imageSpin(t, f.s.peersMu.TryRLock, "peersMu")
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
		f, round := newImageRound(t, 1, 0)
		requireReturned(t, lifecycleClose(f.s), "Close")
		f.refused(t, round, context.Background(), 0, 1, errServiceClosed)
		f.refused(t, round, imageNilCtx, 0, 1, errServiceClosed)
		f.requireRoundRefused(t, context.Background(), f.config(imageTestLimits(), 0), errServiceClosed, "valid config")
		f.requireRoundRefused(t, nil, f.config(imageTestLimits(), 0), errServiceClosed, "nil ctx")
	})
	t.Run("request waiting for writeMu", func(t *testing.T) {
		f := newImageTestFixture(t, 1)
		t0, round := f.clock.Now(), f.round(t, imageTestLimits(), 0)
		release := f.holdWrite(t, 0)
		pending := f.goRequest(round, context.Background(), 0, 1)
		f.waitAdmitted(t, 0, 1, "parked request")
		inst := f.instance(1)
		f.onClose(0, func() { f.clock.set(t0.Add(10*time.Second + time.Nanosecond)) })
		req := f.lockRequester()
		closed := lifecycleClose(f.s)
		requireChannelClosed(t, f.conns[0].closed, "connection close")
		requireStillBlocked(t, closed, "Close with the parked request's end decision pending")
		drainedNil := requestWithin(lifecycleWatchdog, round, imageNilCtx, f.ids[0], 3, imageTestByteLimit)
		drained := requestWithin(lifecycleWatchdog, round, context.Background(), f.ids[0], 2, imageTestByteLimit)
		drainedRound, err := f.begin(context.Background(), f.config(imageTestLimits(), 0))
		req.mu.Unlock()
		requireQueryResult(t, drainedNil, consensus.UTXOImageQuery{}, errServiceClosed, "request with a nil ctx while Close drains")
		requireQueryResult(t, drained, consensus.UTXOImageQuery{}, errServiceClosed, "request while Close drains")
		require(t, drainedRound == nil && err == errServiceClosed, "round while Close drains: round=%v err=%v, want %v", drainedRound != nil, err, errServiceClosed) //nolint:errorlint // The refusal is errServiceClosed itself.
		requireReturned(t, closed, "Close")
		f.requireOwners(t, round, 0, imageOneInstance(0), "after the drained refusals at Close return")
		f.requireEnd(t, inst, errImageExpired, "at Close return")
		requireImageResult(t, awaitImageResult(t, pending, "parked request"), 1, 1, errImageExpired, "parked request")
		_ = release()
		f.requireFrames(t, 0, "parked request")
	})
	t.Run("a request whose admission clock read returns after Close started", func(t *testing.T) { testImageDrainAdmission(t, false) })
	t.Run("a request whose ctx is canceled at an admission clock read that returns after Close started", func(t *testing.T) { testImageDrainAdmission(t, true) })
	t.Run("a request whose lifecycle read returned OPEN completes as admitted when Close starts during its admission", testImageDrainAfterOpenRead)
	t.Run("a round whose clock read returns after Close started", func(t *testing.T) {
		testImageDrainRound(t, time.Unix(1_800_000_000, 0), imageTestLimits(), time.Time{}, func(now time.Time) time.Time { return now })
	})
	t.Run("a round with an inexact RD whose clock read returns after Close started", func(t *testing.T) {
		limits := imageTestLimits()
		limits.RoundLifetime = math.MaxInt64
		testImageDrainRound(t, time.Now(), limits, time.Time{}, func(time.Time) time.Time { return time.Now() })
	})
	t.Run("a round before NotBefore whose clock read returns after Close started", func(t *testing.T) {
		notBefore := time.Unix(1_800_000_060, 0)
		testImageDrainRound(t, time.Unix(1_800_000_000, 0), imageTestLimits(), notBefore, func(time.Time) time.Time { return notBefore.Add(-1) })
	})
	t.Run("request write failed by close", func(t *testing.T) {
		f, round := newImageRound(t, 1, 0)
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

func (f *imageTestFixture) blockNextRead(at func(time.Time) time.Time, onRelease func()) (entered <-chan struct{}, release func()) {
	in, out := make(chan struct{}), make(chan struct{})
	f.clock.onNextRead(func(now time.Time) time.Time { close(in); <-out; onRelease(); return at(now) })
	return in, func() { close(out) }
}

func (f *imageTestFixture) closeWhileReadHeld(t *testing.T, entered <-chan struct{}, release func()) chan error {
	t.Helper()
	requireChannelClosed(t, entered, "held clock read")
	closed := lifecycleClose(f.s)
	waitDraining(t, f.s)
	requireStillBlocked(t, closed, "Close with the clock read held")
	release()
	return closed
}

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
	f.requireFaultsKept(t, []imageFault{{closes: 1}, {closes: 1}}, "drained admission")
	f.requireCurrentAfterUnwind(t, round, first, [2]uint64{1, 1})
	f.requireOwners(t, round, 1, refusing, "drained admission")
	f.requireFrames(t, 1, "drained admission")
}

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

func testImageDrainRound(t *testing.T, start time.Time, limits ImageLimits, notBefore time.Time, at func(time.Time) time.Time) {
	f := newImageTestFixtureAt(t, 1, start)
	registry := f.owners(nil, 0)
	entered, release := f.blockNextRead(at, func() {})
	config := f.config(limits, 0)
	config.NotBefore = notBefore
	done := make(chan imageBegin, 1)
	go func() {
		round, err := f.s.BeginImageRound(context.Background(), config)
		done <- imageBegin{round, err}
	}()
	closed := f.closeWhileReadHeld(t, entered, release)
	got, ok := receiveWithin(done, lifecycleWatchdog)
	require(t, ok && got.round == nil && got.err == errServiceClosed, "round after Close started: returned=%v round=%v err=%v, want %v", ok, got.round != nil, got.err, errServiceClosed) //nolint:errorlint // The refusal is errServiceClosed itself.
	requireReturned(t, closed, "Close")
	f.requireOwners(t, nil, 0, registry, "round after Close started")
	f.requireFaultsKept(t, []imageFault{{closes: 1}}, "round after Close started")
}

type imageCloser struct {
	request         bool
	lastError       string
	perPeer, global imageUnitVector
}

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
			record.perPeer, record.global = *cmp.Or(round.perPeer[p], &imageUnitVector{}), round.global
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
	return func() []imageCloser { mu.Lock(); defer mu.Unlock(); return slices.Clone(records) }
}

const imageUnwindSentinel = "image requester test unwind"

func testImageUnwind(t *testing.T) {
	stop := func(name string, atRD, roundCtx, pass bool) {
		var unreachable func() bool
		t.Run(name, func(t *testing.T) { unreachable = testImageUnwindStop(t, atRD, roundCtx, pass) })
		require(t, unreachable == nil || unreachable(), "%s: Service reachable after Close and the retirement of its instances", name)
	}
	t.Run("a panic in the clock read of the pre-write decision made with writeMu acquired", func(t *testing.T) { testImageUnwindWithWriteMu(t, false) })
	t.Run("runtime.Goexit in the clock read of the pre-write decision made with writeMu acquired", func(t *testing.T) { testImageUnwindWithWriteMu(t, true) })
	t.Run("a panic in a clock read made after a failed TryLock", testImageUnwindWaiting)
	t.Run("a panic in the connection write of the request frame", testImageUnwindWrite)
	t.Run("a panic in the AfterFunc method of the request ctx at admission", func(t *testing.T) { testImageUnwindArming(t, false, false, true) })
	t.Run("runtime.Goexit in the AfterFunc method of the request ctx at admission", func(t *testing.T) { testImageUnwindArming(t, true, false, true) })
	t.Run("a panic in the AfterFunc method of the round ctx at admission", func(t *testing.T) { testImageUnwindArming(t, false, true, true) })
	t.Run("runtime.Goexit in the AfterFunc method of the round ctx at admission", func(t *testing.T) { testImageUnwindArming(t, true, true, true) })
	t.Run("a panic in the round ctx AfterFunc method with the request ctx callback first run after the unwind", func(t *testing.T) { testImageUnwindArming(t, false, true, false) })
	t.Run("runtime.Goexit in the round ctx AfterFunc method with the request ctx callback first run after the unwind", func(t *testing.T) { testImageUnwindArming(t, true, true, false) })
	stop("a panic in the stop call of the pre-write retirement with D before RD", false, false, false)
	stop("a panic in the stop call of the pre-write retirement at RD with D equal to RD", true, false, false)
	stop("a panic in the round ctx stop call of the pre-write retirement with D before RD", false, true, false)
	t.Run("a round ctx callback after a panic in the stop call of the pre-write retirement retires the instance", testImageUnwindStopRoundEnd)
	stop("a panic in the request ctx stop call of another request's pass retiring the instance", false, false, true)
	stop("a panic in the round ctx stop call of another request's pass retiring the instance", false, true, true)
	t.Run("a panic in the request ctx stop call of the retirement after a failed write", func(t *testing.T) { testImageUnwindFailedWrite(t, false, false, -1) })
	t.Run("runtime.Goexit in the request ctx stop call of the retirement after a failed write", func(t *testing.T) { testImageUnwindFailedWrite(t, true, false, -1) })
	t.Run("a panic in the round ctx stop call of the retirement after a failed write", func(t *testing.T) { testImageUnwindFailedWrite(t, false, true, -1) })
	t.Run("the same with a second request held on another session", func(t *testing.T) { testImageUnwindFailedWrite(t, false, false, 1) })
	t.Run("the same with a second request held on the session", func(t *testing.T) { testImageUnwindFailedWrite(t, false, false, 0) })
}

func imageUnwindCtx(c *imageHookCtx, live context.Context, roundCtx bool) (context.Context, context.Context) {
	if roundCtx {
		return c, live
	}
	return live, c
}

func imageUnwinder(goexit bool) func() {
	return func() {
		if goexit {
			runtime.Goexit()
		}
		panic(imageUnwindSentinel)
	}
}

func (f *imageTestFixture) requireUnwound(t *testing.T, done <-chan any, goexit bool) {
	t.Helper()
	recovered, want := awaitImageResult(t, done, "unwinding request"), map[bool]any{false: imageUnwindSentinel, true: imageGoexit}[goexit]
	require(t, recovered == want, "recovered %v, want %v", recovered, want)
	f.requireRequesterFree(t)
}

// sync.WaitGroup starts with its state word, the counter in the high 32 bits: the Service leases held.
func (f *imageTestFixture) leases() uint64 {
	return (*atomic.Uint64)(unsafe.Pointer(&f.s.loopWG)).Load() >> 32
}

func (f *imageTestFixture) requireRequesterFree(t *testing.T) {
	t.Helper()
	require(t, f.s.imageRequester.mu.TryLock(), "requester mutex still held after the unwinding request ended")
	f.s.imageRequester.mu.Unlock()
}

func (f *imageTestFixture) requireCurrentAfterUnwind(t *testing.T, round *ImageRound, inst *imageInstance, current [2]uint64) {
	t.Helper()
	retired, end := f.ended(inst)
	perPeer, global := f.usage(round, 0)
	got := [2]uint64{perPeer[unitCurrentAssignments], global[unitCurrentAssignments]}
	require(t, inst != nil && f.instance(1) == inst && !retired && end == nil && got == current, "after the unwind: registered=%v retired=%v end=%v current assignments per peer and global %v, want registered, unretired, no end, %v", f.instance(1) == inst, retired, end, got, current)
}

func testImageUnwindFailedWrite(t *testing.T, goexit, roundCtx bool, holder int) {
	f, limits := newImageTestFixture(t, 2), imageUnwindLimits(24*time.Hour, 48*time.Hour)
	if holder >= 0 {
		limits = imageTestLimits(24*time.Hour, 48*time.Hour)
		limits.Global.PendingNetworkBytes = 240
	}
	c := newImageHookCtx()
	c.onStop = imageUnwinder(goexit)
	roundC, requestC := imageUnwindCtx(c, context.Background(), roundCtx)
	round := f.roundCtx(t, roundC, limits, 0, 1)
	stall := f.wires[0].armStallAfter(1)
	unwound := f.goRecovered(round, requestC, 0, 1)
	requireChannelClosed(t, stall.entered, "payload write of the unwinding request")
	inst, stallB, held := f.instance(1), (*imageStall)(nil), (<-chan imageResult)(nil)
	if holder >= 0 {
		stallB = f.wires[holder].armStallAfter(0)
		held = f.goRequest(round, context.Background(), holder, 2)
		f.waitAdmitted(t, holder, uint64(2-holder), "second holder")
	}
	pending := [2]uint64{math.MaxUint64, math.MaxUint64}
	// A close made under the requester mutex blocks this hook past the request's lifecycleWatchdog bound.
	f.onClose(0, func() {
		if stallB != nil {
			<-stallB.entered
		}
		perPeer, global := f.usage(round, 0)
		pending = [2]uint64{perPeer[unitPendingNetworkBytes], global[unitPendingNetworkBytes]}
	})
	stall.release <- errImageScriptedWrite
	if holder == 0 {
		requireImageResult(t, awaitImageResult(t, held, "second holder"), 2, 2, net.ErrClosed, "second holder")
	}
	f.requireUnwound(t, unwound, goexit)
	require(t, len(f.wires[0].bytes()) == wireHeaderSize, "after the unwind: %d bytes written, want the %d header bytes", len(f.wires[0].bytes()), wireHeaderSize)
	requireEqual(t, pending, [2]uint64{map[int]uint64{0: 120}[holder], map[bool]uint64{true: 120}[holder >= 0]}, "pending request bytes per peer and global inside the close hook")
	if holder == 1 {
		// Start 3 brings the global pending bytes from 120 to 240 and fits; start 4 would bring them to 360 and refuses.
		next := f.goRequest(round, context.Background(), 1, 3)
		f.waitAdmitted(t, 1, 2, "request at the global limit")
		f.refused(t, round, context.Background(), 1, 4, errImageLimit)
		stallB.release <- nil
		requireImageResult(t, awaitImageResult(t, held, "second holder"), 1, 2, nil, "second holder")
		requireImageResult(t, awaitImageResult(t, next, "request at the global limit"), 2, 3, nil, "request at the global limit")
	}
	f.requireFault(t, 0, 1+map[int]int{0: 1}[holder], map[bool]string{true: net.ErrClosed.Error(), false: errImageScriptedWrite.Error()}[holder == 0], "at the end")
	f.requireCurrentAfterUnwind(t, round, inst, [2]uint64{1, 1 + map[int]uint64{1: 2}[holder]})
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	requireReturned(t, lifecycleClose(f.s), "Close")
}

func imageUnwindLimits(lifetimes ...time.Duration) ImageLimits {
	limits := imageTestLimits(lifetimes...)
	limits.PerPeer.PendingNetworkBytes, limits.Global.PendingNetworkBytes = 120, 120
	return limits
}

func (f *imageTestFixture) unwindAtPreWriteRead(unwind func()) {
	f.clock.onReadFrom(".(*ImageRound).endBeforeWrite", func(now time.Time) time.Time { unwind(); return now })
}

const imageGoexit = "goroutine exited"

func (f *imageTestFixture) goRecovered(round *ImageRound, ctx context.Context, session int, start byte) <-chan any {
	done := make(chan any, 1)
	go func() {
		result := any(imageGoexit)
		defer func() { done <- cmp.Or(recover(), result) }()
		q, err := round.Request(ctx, f.ids[session], imageStart(start), imageTestByteLimit)
		result = imageResult{q, err}
	}()
	return done
}

func (f *imageTestFixture) requireNextAfterUnwind(t *testing.T, round *ImageRound, session int, start byte, wantID uint64) {
	t.Helper()
	got, returned := receiveWithin(f.goRequest(round, t.Context(), session, start), lifecycleWatchdog)
	if returned {
		requireImageResult(t, got, wantID, start, nil, "request after the unwind")
	}
	f.requireFrames(t, session, "request after the unwind", expectedImageQuery(wantID, start))
	require(t, returned, "request after the unwind did not return within %s", lifecycleWatchdog)
}

func testImageUnwindWithWriteMu(t *testing.T, goexit bool) {
	f := newImageTestFixture(t, 2)
	round := f.round(t, imageUnwindLimits(), 0, 1)
	f.unwindAtPreWriteRead(imageUnwinder(goexit))
	f.requireUnwound(t, f.goRecovered(round, context.Background(), 0, 1), goexit)
	f.requireFrames(t, 0, "after the unwind")
	f.requireNextAfterUnwind(t, round, 0, 2, 2)
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.requireFault(t, 0, 0, "", "after the unwind")
	requireReturned(t, lifecycleClose(f.s), "Close")
}

func testImageUnwindWaiting(t *testing.T) {
	f := newImageTestFixture(t, 1)
	round := f.round(t, imageUnwindLimits(), 0)
	f.peers[0].writeMu.Lock()
	f.unwindAtPreWriteRead(func() { panic(imageUnwindSentinel) })
	f.requireUnwound(t, f.goRecovered(round, context.Background(), 0, 1), false)
	pending := f.goRequest(round, t.Context(), 0, 2)
	f.waitAdmitted(t, 0, 2, "request after the unwind")
	_, returned := receiveWithin(pending, lifecycleSettle)
	f.requireFrames(t, 0, "while the test holds writeMu")
	require(t, !returned, "request after the unwind returned while the test held writeMu")
	for range 3 {
		requireChannelClosed(t, f.clock.readFrom(".(*ImageRound).endBeforeWrite"), "pre-write clock read of the request waiting for writeMu")
	}
	f.peers[0].writeMu.Unlock()
	requireImageResult(t, awaitImageResult(t, pending, "request after the unwind"), 2, 2, nil, "request after the unwind")
	f.requireFrames(t, 0, "after the test released writeMu", expectedImageQuery(2, 2))
	requireReturned(t, lifecycleClose(f.s), "Close")
}

func testImageUnwindWrite(t *testing.T) {
	for skip := range 2 {
		f := newImageTestFixture(t, 1)
		round := f.round(t, imageUnwindLimits(), 0)
		f.wires[0].mu.Lock()
		f.wires[0].panicNext, f.wires[0].panicSkip = imageUnwindSentinel, skip
		f.wires[0].mu.Unlock()
		f.requireUnwound(t, f.goRecovered(round, context.Background(), 0, 1), false)
		requireEqual(t, len(f.wires[0].bytes()), skip*wireHeaderSize, "bytes written by the panicking frame write")
		f.wires[0].drop(skip * wireHeaderSize)
		f.requireNextAfterUnwind(t, round, 0, 2, 2)
		f.requireFault(t, 0, 0, "", "after the unwind")
		requireReturned(t, lifecycleClose(f.s), "Close")
	}
}

func testImageUnwindArming(t *testing.T, goexit, roundCtx, parked bool) {
	inImageBubble(func(t *testing.T) {
		c, cr, ran, f := newImageHookCtx(), newImageHookCtx(), make(chan int, 1), newImageTestFixture(t, 2)
		roundC, requestC := imageUnwindCtx(c, cr, roundCtx)
		round, leases, reads := f.roundCtx(t, roundC, imageUnwindLimits(), 0, 1), f.leases(), f.clock.readCount()
		c.onAfterFunc = func() {
			if roundCtx && parked {
				waitImageMutexWaiter(t, &f.s.imageRequester.mu, func() { go func() { ran <- cr.endAndRun(context.Canceled) }() })
			}
			imageUnwinder(goexit)()
		}
		unwound := f.goRecovered(round, requestC, 0, 1)
		if roundCtx && parked {
			requireEqual(t, awaitImageResult(t, ran, "Request ctx functions"), 1, "Request ctx functions run")
			imageSpin(t, func() bool { return f.leases() == leases }, "Service lease release by the Request ctx callback")
			require(t, f.clock.readCount() == reads+1 && cr.applierErrs == 0 && f.instance(1) == nil, "Request ctx callback waiting through the unwind: clock reads %d->%d, Err calls %d, registered %v, want only the admission read", reads, f.clock.readCount(), cr.applierErrs, f.instance(1) != nil)
			f.requireUsage(t, round, 0, imageUnitVector{}, imageUnitVector{}, "after the Request ctx callback waiting through the unwind")
		}
		f.requireUnwound(t, unwound, goexit)
		f.requireNextAfterUnwind(t, round, 0, 1, 1)
		f.admitted(t, round, context.Background(), 0, 2, 2)
		g := newImageTestFixture(t, 2)
		fresh := g.round(t, imageUnwindLimits(), 0, 1)
		g.admitted(t, fresh, context.Background(), 0, 1, 1)
		g.admitted(t, fresh, context.Background(), 0, 2, 2)
		wantPerPeer, wantGlobal := g.usage(fresh, 0)
		f.requireUsage(t, round, 0, wantPerPeer, wantGlobal, "after the next requests")
		if roundCtx {
			synctest.Wait()
			req, leases, stacks, probe := f.lockRequester(), f.leases(), make([]byte, 1<<20), make(chan struct{}, 1<<16)
			created := fmt.Appendf(nil, "created by context.(*afterFuncCtx).cancel.func1 in goroutine %s\n", bytes.Fields(stacks[:runtime.Stack(stacks, false)])[1])
			func() {
				defer req.mu.Unlock()
				requireEqual(t, cr.endAndRun(errImageRequestEnd), 1, "Cr functions run after Cr ends")
				probeCtx, cancelProbe := context.WithCancel(context.Background())
				context.AfterFunc(probeCtx, func() { <-probe })
				cancelProbe()
				for scans, seen := 0, true; seen; scans++ {
					n := runtime.Stack(stacks, true)
					seen = bytes.Contains(stacks[:n], created)
					require(t, n < len(stacks) && f.leases() == leases && scans < 1<<16 && (seen || scans > 0), "Cr callback of the unwound call: stack dump of %d bytes, Service leases %d->%d after %d stack scans, seen %v, want an untruncated dump, the AfterFunc goroutines in the first scan, no lease and its return", n, leases, f.leases(), scans, seen)
					probe <- struct{}{}
					runtime.Gosched()
				}
			}()
			synctest.Wait()
			f.requireUsage(t, round, 0, wantPerPeer, wantGlobal, "after Cr is canceled")
			f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
			f.requireEnd(t, f.instance(1), nil, "instance of start 1 after Cr is canceled")
		}
		requireReturned(t, lifecycleClose(f.s), "Close")
	})(t)
}

func testImageUnwindStop(t *testing.T, atRD, roundCtx, pass bool) func() bool {
	f := newImageTestFixture(t, 2)
	t0, limits := f.clock.Now(), imageUnwindLimits(24*time.Hour, 48*time.Hour)
	end := t0.Add(24*time.Hour + time.Nanosecond)
	if atRD {
		limits.RoundLifetime, end = 24*time.Hour, t0.Add(24*time.Hour)
	}
	c, nextCtx := newImageHookCtx(), newImageHookCtx()
	c.onStop = func() { panic(imageUnwindSentinel) }
	roundC, _ := imageUnwindCtx(c, context.Background(), roundCtx)
	round := f.roundCtx(t, roundC, limits, 0, 1)
	inst, release := f.unwindRetirement(t, round, c, roundCtx, end, pass)
	f.requireRequesterFree(t)
	f.requireCurrentAfterUnwind(t, round, inst, [2]uint64{1, 1})
	f.requireUsage(t, round, 0, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 1, 1, 0), "after the stop call unwound")
	next := round
	if atRD {
		next = f.round(t, limits, 0, 1)
		f.refused(t, next, context.Background(), 1, 1, errImageAssignmentCurrent)
		f.clock.add(time.Nanosecond)
	}
	following := f.admitted(t, next, nextCtx, 1, 1, 1)
	f.requireEnd(t, inst, errImageExpired, "unwound instance after the next request")
	held, svc := weak.Make(inst), weak.Make(f.s)
	runtime.GC()
	require(t, held.Value() == nil, "unwound instance reachable through its ctx after its retirement completed")
	runtime.KeepAlive(c)
	if !atRD {
		f.requireUsage(t, round, 1, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after session 1's request")
	}
	release()
	f.requireFault(t, 0, 0, "", "after the unwind")
	requireEqual(t, nextCtx.endAndRun(errImageRequestEnd), 1, "Request ctx functions of the next request")
	imageSpin(t, func() bool { _, end := f.ended(following); return errors.Is(end, errImageRequestEnd) }, "next request retired by its Request ctx")
	requireReturned(t, lifecycleClose(f.s), "Close")
	return func() bool { runtime.GC(); return svc.Value() == nil && c != nil }
}

func testImageUnwindStopRoundEnd(t *testing.T) {
	f := newImageTestFixture(t, 1)
	c, roundCtx := newImageHookCtx(), newImageHookCtx()
	c.onStop = func() { panic(imageUnwindSentinel) }
	round := f.roundCtx(t, roundCtx, imageUnwindLimits(24*time.Hour, 48*time.Hour), 0)
	inst, release := f.unwindRetirement(t, round, c, false, f.clock.Now().Add(24*time.Hour+time.Nanosecond), false)
	requireEqual(t, roundCtx.endAndRun(errImageRoundEnd), 1, "round ctx functions")
	imageSpin(t, func() bool { retired, _ := f.ended(inst); return retired }, "round ctx callback retirement")
	f.requireEnd(t, inst, errImageRoundEnd, "unwound instance after its round ctx ended")
	release()
}

func (f *imageTestFixture) unwindRetirement(t *testing.T, round *ImageRound, c *imageHookCtx, roundCtx bool, end time.Time, pass bool) (*imageInstance, func()) {
	t.Helper()
	_, ctx := imageUnwindCtx(c, context.Background(), roundCtx)
	if pass {
		inst := f.admitted(t, round, ctx, 0, 1, 1)
		f.clock.set(end)
		requireEqual(t, awaitImageResult(t, f.goRecovered(round, context.Background(), 1, 2), "unwinding request"), any(imageUnwindSentinel), "value the unwinding request panicked with")
		return inst, func() {}
	}
	f.peers[0].writeMu.Lock()
	unwound := f.goRecovered(round, ctx, 0, 1)
	f.waitAdmitted(t, 0, 1, "request waiting for writeMu")
	inst := f.instance(1)
	f.clock.set(end)
	requireEqual(t, awaitImageResult(t, unwound, "request waiting for writeMu"), any(imageUnwindSentinel), "value the unwinding request panicked with")
	return inst, func() {
		require(t, !f.peers[0].writeMu.TryLock(), "writeMu released while the test held it")
		f.peers[0].writeMu.Unlock()
	}
}
