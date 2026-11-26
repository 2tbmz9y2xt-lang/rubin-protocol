package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"weak"
)

const imageUnwindSentinel = "image requester test unwind"

var errImageWritePanic = errors.New("image test write panic")

func TestImageRequesterUnwind(t *testing.T) {
	t.Run("clock panic with writeMu acquired", func(t *testing.T) { testImageUnwindHeld(t, false, false) })
	t.Run("clock Goexit with writeMu acquired", func(t *testing.T) { testImageUnwindHeld(t, true, false) })
	t.Run("request Err panic with writeMu acquired", func(t *testing.T) { testImageUnwindHeld(t, false, true) })
	t.Run("clock panic while waiting for writeMu", testImageUnwindWaiting)
	t.Run("write panic in header", func(t *testing.T) { testImageUnwindWrite(t, 0) })
	t.Run("write panic in payload", func(t *testing.T) { testImageUnwindWrite(t, 1) })
	t.Run("write unwind releases global pending bytes once", func(t *testing.T) { testImageUnwindPending(t, false) })
	t.Run("write unwind releases session pending bytes once", func(t *testing.T) { testImageUnwindPending(t, true) })
	testImageArmingUnwinds(t)
	testImageRetirementUnwinds(t)
	testImageFailedWriteUnwinds(t)
}

func (w *imageWire) drop(n int) { w.mu.Lock(); w.sent = w.sent[n:]; w.mu.Unlock() }

type imageUnwindHookCtx struct {
	*imageHookCtx
	errReads            atomic.Int32
	doneOnce, valueOnce sync.Once
	onErr, onDone       func()
	onValue             func()
}

func (c *imageUnwindHookCtx) Err() error {
	if c.onErr != nil && c.errReads.Add(1) == 3 {
		c.onErr()
	}
	return c.imageHookCtx.Err()
}

func (c *imageUnwindHookCtx) Done() <-chan struct{} {
	if c.onDone != nil {
		c.doneOnce.Do(c.onDone)
	}
	return c.imageHookCtx.Done()
}

func (c *imageUnwindHookCtx) Value(key any) any {
	if c.onValue != nil {
		c.valueOnce.Do(c.onValue)
	}
	return c.imageHookCtx.Value(key)
}

func imageUnwinder(goexit bool) func() {
	return func() {
		if goexit {
			runtime.Goexit()
		}
		panic(imageUnwindSentinel)
	}
}

func requireImageUnwindReport(t *testing.T, done <-chan any, goexit bool) {
	t.Helper()
	want := imageUnwindSentinel
	if goexit {
		want = imageGoexit
	}
	requireEqual(t, awaitImageResult(t, done, "unwinding request"), any(want), "unwind report")
}

func (f *imageTestFixture) requireRequesterFree(t *testing.T) {
	t.Helper()
	req := f.s.imageRequester
	require(t, req.mu.TryLock(), "requester mutex still held after the unwinding request ended")
	req.mu.Unlock()
}

func (f *imageTestFixture) requireUnwound(t *testing.T, done <-chan any, goexit bool) {
	t.Helper()
	requireImageUnwindReport(t, done, goexit)
	f.requireRequesterFree(t)
}

func imageUnwindLimits(lifetimes ...time.Duration) ImageLimits {
	limits := imageTestLimits(lifetimes...)
	limits.PerPeer.PendingNetworkBytes, limits.Global.PendingNetworkBytes = 120, 120
	return limits
}

func (f *imageTestFixture) unwindAtPreWriteRead(unwind func()) {
	f.clock.onReadFrom(".(*ImageRound).endBeforeWrite", func(now time.Time) time.Time { unwind(); return now })
}

func (f *imageTestFixture) requireNextAfterUnwind(t *testing.T, round *ImageRound, session int, start byte, wantID uint64) {
	t.Helper()
	got := awaitImageResult(t, f.goRequest(round, t.Context(), session, start), "request after the unwind")
	requireImageResult(t, got, wantID, start, nil, "request after the unwind")
	f.requireFrames(t, session, "request after the unwind", expectedImageQuery(wantID, start))
}

func (f *imageTestFixture) requireUnwindInstance(t *testing.T, round *ImageRound, inst *imageInstance) {
	t.Helper()
	f.requireCurrentAfterUnwind(t, round, inst, [2]uint64{1, 1})
	want := imageUsage(1, 1, 1, 1, 0)
	f.requireUsage(t, round, 0, want, want, "after the unwind")
}

func testImageUnwindHeld(t *testing.T, goexit, errHook bool) {
	f := newImageTestFixture(t, 2)
	round := f.round(t, imageUnwindLimits(), 0, 1)
	ctx := context.Background()
	if errHook {
		ctx = &imageUnwindHookCtx{imageHookCtx: newImageHookCtx(), onErr: imageUnwinder(false)}
	} else {
		f.unwindAtPreWriteRead(imageUnwinder(goexit))
	}
	f.requireUnwound(t, f.goRecovered(round, ctx, 0, 1), goexit)
	f.requireFrames(t, 0, "after the unwind")
	f.requireUnwindInstance(t, round, f.instance(1))
	f.requireNextAfterUnwind(t, round, 0, 2, 2)
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.requireFault(t, 0, 0, "", "after the unwind")
	requireReturned(t, lifecycleClose(f.s), "Close")
}

func testImageUnwindWaiting(t *testing.T) {
	f := newImageTestFixture(t, 2)
	round := f.round(t, imageUnwindLimits(), 0, 1)
	f.peers[0].writeMu.Lock()
	f.unwindAtPreWriteRead(imageUnwinder(false))
	f.requireUnwound(t, f.goRecovered(round, context.Background(), 0, 1), false)
	f.requireUnwindInstance(t, round, f.instance(1))
	pending := f.goRequest(round, t.Context(), 0, 2)
	f.waitAdmitted(t, 0, 2, "request after the unwind")
	got, returned := receiveWithin(pending, lifecycleSettle)
	f.requireFrames(t, 0, "while the test holds writeMu")
	require(t, !returned, "request returned %+v while the test held writeMu", got)
	for range 3 {
		requireChannelClosed(t, f.clock.readFrom(".(*ImageRound).endBeforeWrite"), "pre-write clock read of the waiting request")
	}
	f.peers[0].writeMu.Unlock()
	requireImageResult(t, awaitImageResult(t, pending, "request after the unwind"), 2, 2, nil, "request after the unwind")
	f.requireFrames(t, 0, "after the test released writeMu", expectedImageQuery(2, 2))
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	requireReturned(t, lifecycleClose(f.s), "Close")
}

func requireUnwindWritePrefix(t *testing.T, wire *imageWire, wantBytes int) {
	t.Helper()
	got := wire.bytes()
	requireEqual(t, len(got), wantBytes, "bytes accepted from the unwinding write")
	if wantBytes == wireHeaderSize {
		requireEqual(t, [12]byte(got[4:16]), imageRequestCommand, "command bytes of the admitted frame header")
	}
}

func testImageUnwindWrite(t *testing.T, skip int) {
	f := newImageTestFixture(t, 2)
	round := f.round(t, imageUnwindLimits(), 0, 1)
	wire := f.wires[0]
	wire.mu.Lock()
	wire.panicNext, wire.panicSkip = imageUnwindSentinel, skip
	wire.mu.Unlock()
	f.requireUnwound(t, f.goRecovered(round, context.Background(), 0, 1), false)
	requireUnwindWritePrefix(t, wire, skip*wireHeaderSize)
	f.requireUnwindInstance(t, round, f.instance(1))
	wire.drop(skip * wireHeaderSize)
	f.requireNextAfterUnwind(t, round, 0, 2, 2)
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	f.requireFault(t, 0, 0, "", "after the unwind")
	requireReturned(t, lifecycleClose(f.s), "Close")
}

func testImageUnwindPending(t *testing.T, perPeer bool) {
	f, limits := newImageTestFixture(t, 2), imageTestLimits()
	session, idB := 1, uint64(1)
	limits.Global.PendingNetworkBytes = 240
	if perPeer {
		session, idB = 0, 2
		limits.PerPeer.PendingNetworkBytes, limits.Global.PendingNetworkBytes = 240, 1<<20
	}
	round := f.round(t, limits, 0, 1)
	stallA := f.wires[0].armStallAfter(0)
	doneA := f.goRecovered(round, context.Background(), 0, 1)
	requireChannelClosed(t, stallA.entered, "write of holder A")
	stallB := f.wires[session].armStallAfter(0)
	heldB := f.goRequest(round, context.Background(), session, 2)
	f.waitAdmitted(t, session, idB, "holder B")
	stallA.release <- errImageWritePanic
	requireImageUnwindReport(t, doneA, false)
	requireChannelClosed(t, stallB.entered, "write of holder B")
	f.requireRequesterFree(t)
	nextC := f.goRequest(round, context.Background(), session, 3)
	f.waitAdmitted(t, session, idB+1, "request C")
	per, global := f.usage(round, session)
	requireEqual(t, [2]uint64{per[unitPendingNetworkBytes], global[unitPendingNetworkBytes]}, [2]uint64{240, 240}, "pending bytes on holder B's session and globally")
	f.refused(t, round, context.Background(), session, 4, errImageLimit)
	stallB.release <- nil
	requireImageResult(t, awaitImageResult(t, heldB, "holder B"), idB, 2, nil, "holder B")
	requireImageResult(t, awaitImageResult(t, nextC, "request C"), idB+1, 3, nil, "request C")
	requireReturned(t, lifecycleClose(f.s), "Close")
}

type imageArmingUnwindCase struct {
	name                     string
	goexit, roundCtx, parked bool
	hook                     func(*imageUnwindHookCtx)
}

func testImageArmingUnwinds(t *testing.T) {
	for _, tc := range []imageArmingUnwindCase{
		{name: "request AfterFunc panic before publication"},
		{name: "request AfterFunc Goexit before publication", goexit: true},
		{name: "request Done panic before publication", hook: func(c *imageUnwindHookCtx) { c.onDone = imageUnwinder(false) }},
		{name: "request Value panic before publication", hook: func(c *imageUnwindHookCtx) { c.onValue = imageUnwinder(false) }},
		{name: "round AfterFunc panic before publication", roundCtx: true},
		{name: "round AfterFunc Goexit before publication", goexit: true, roundCtx: true},
		{name: "round AfterFunc panic with request callback parked", roundCtx: true, parked: true},
		{name: "round AfterFunc Goexit with request callback parked", goexit: true, roundCtx: true, parked: true},
	} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) { testImageUnwindArming(t, tc) }))
	}
}

func testImageUnwindArming(t *testing.T, tc imageArmingUnwindCase) {
	f := newImageTestFixture(t, 2)
	c, cr := newImageHookCtx(), newImageHookCtx()
	roundCtx, requestCtx := imageUnwindCtx(c, cr, tc.roundCtx)
	round := f.roundCtx(t, roundCtx, imageUnwindLimits(), 0, 1)
	leases, reads := f.leases(), f.clock.readCount()
	ran := make(chan int, 1)
	if tc.hook != nil {
		hooked := &imageUnwindHookCtx{imageHookCtx: c}
		tc.hook(hooked)
		requestCtx = hooked
	} else {
		c.onAfterFunc = func() {
			if tc.parked {
				f.parkUnarmedImageCallback(t, cr, ran)
			}
			imageUnwinder(tc.goexit)()
		}
	}
	requireImageUnwindReport(t, f.goRecovered(round, requestCtx, 0, 1), tc.goexit)
	if tc.parked {
		f.requireParkedArmingUnwind(t, round, cr, ran, leases, reads)
	} else {
		f.requireRequesterFree(t)
	}
	f.requireNextAfterUnwind(t, round, 0, 1, 1)
	f.admitted(t, round, context.Background(), 0, 2, 2)
	f.requireFrames(t, 0, "after the next requests", expectedImageQuery(1, 1), expectedImageQuery(2, 2))
	want := imageUsage(2, 2, 2, 2, 0)
	f.requireUsage(t, round, 0, want, want, "after the next requests")
	f.requireFault(t, 0, 0, "", "after the arming unwind")
	if tc.roundCtx {
		f.requireUnarmedCallbackIdle(t, cr)
		f.requireUsage(t, round, 0, want, want, "after the unwound request context ends")
		f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
		f.requireEnd(t, f.instance(1), nil, "later instance after the unwound request context ends")
	}
	requireReturned(t, lifecycleClose(f.s), "Close")
}

func (f *imageTestFixture) parkUnarmedImageCallback(t *testing.T, cr *imageHookCtx, ran chan<- int) {
	t.Helper()
	f.clock.onReadFrom("p2p.applyImageEnd", func(now time.Time) time.Time { runtime.Goexit(); return now })
	waitImageMutexWaiter(t, &f.s.imageRequester.mu, func() {
		go func() { ran <- cr.endAndRun(context.Canceled) }()
	})
}

func (f *imageTestFixture) requireParkedArmingUnwind(t *testing.T, round *ImageRound, cr *imageHookCtx, ran <-chan int, leases uint64, reads int) {
	t.Helper()
	requireEqual(t, awaitImageResult(t, ran, "request context functions"), 1, "request context functions run")
	imageSpin(t, func() bool { return f.leases() == leases }, "Service lease release by the request context callback")
	f.requireRequesterFree(t)
	cr.mu.Lock()
	errReads := cr.applierErrs
	cr.mu.Unlock()
	requireEqual(t, f.clock.readCount(), reads+1, "clock reads after the parked callback")
	requireEqual(t, errReads, 0, "request context Err reads from the parked callback")
	require(t, f.instance(1) == nil, "unpublished start has a registered instance")
	f.requireUsage(t, round, 0, imageUnitVector{}, imageUnitVector{}, "after the parked callback")
	f.clock.onNextRead(nil)
}

func (f *imageTestFixture) requireUnarmedCallbackIdle(t *testing.T, cr *imageHookCtx) {
	t.Helper()
	synctest.Wait()
	func() {
		req := f.lockRequester()
		defer req.mu.Unlock()
		leases := f.leases()
		stacks := make([]byte, 1<<20)
		id := bytes.Fields(stacks[:runtime.Stack(stacks, false)])[1]
		creator := fmt.Appendf(nil, "created by context.(*afterFuncCtx).cancel.func1 in goroutine %s\n", id)
		requireEqual(t, cr.endAndRun(errImageRequestEnd), 1, "request context functions run after the retry")
		probe, canceled := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(probe) })
		defer release()
		probeCtx, cancelProbe := context.WithCancel(context.Background())
		context.AfterFunc(probeCtx, func() { close(canceled); <-probe })
		cancelProbe()
		requireChannelClosed(t, canceled, "probe AfterFunc started")
		for scan := range 1 << 16 {
			n := runtime.Stack(stacks, true)
			require(t, n < len(stacks), "goroutine stack dump truncated at %d bytes", n)
			count := bytes.Count(stacks[:n], creator)
			require(t, scan != 0 || count > 0, "first stack scan found %d AfterFunc goroutines", count)
			requireEqual(t, f.leases(), leases, "Service leases while the requester mutex is held")
			if count == 0 {
				return
			}
			release()
			runtime.Gosched()
		}
		t.Fatal("AfterFunc goroutines remained after 65536 stack scans")
	}()
	synctest.Wait()
}

type imageStopUnwindCase struct {
	name                 string
	roundCtx, atRD, pass bool
}

func testImageRetirementUnwinds(t *testing.T) {
	for _, tc := range []imageStopUnwindCase{
		{name: "request stop panic before write after expiry"},
		{name: "round stop panic before write after expiry", roundCtx: true},
		{name: "request stop panic before write at the round deadline", atRD: true},
		{name: "request stop panic in the next admission pass", pass: true},
		{name: "round stop panic in the next admission pass", roundCtx: true, pass: true},
	} {
		var serviceReleased func() bool
		if t.Run(tc.name, func(t *testing.T) { serviceReleased = testImageUnwindStop(t, tc) }) {
			require(t, serviceReleased(), "%s: Service reachable after the fixture closed and retired its instances", tc.name)
		}
	}
	t.Run("round end completes a retirement after a stop panic", testImageUnwindRoundEnd)
	t.Run("timer completes a retirement after a stop panic", testImageUnwindTimerEnd)
}

func testImageUnwindStop(t *testing.T, tc imageStopUnwindCase) func() bool {
	f := newImageTestFixture(t, 2)
	limits := imageUnwindLimits(24*time.Hour, 48*time.Hour)
	end := f.clock.Now().Add(24*time.Hour + time.Nanosecond)
	if tc.atRD {
		limits.RoundLifetime = 24 * time.Hour
		end = end.Add(-time.Nanosecond)
	}
	c, nextCtx := newImageHookCtx(), newImageHookCtx()
	c.onStop = imageUnwinder(false)
	roundCtx, requestCtx := imageUnwindCtx(c, context.Background(), tc.roundCtx)
	round := f.roundCtx(t, roundCtx, limits, 0, 1)
	inst := f.unwindRetirement(t, round, requestCtx, end, tc.pass)
	f.requireRequesterFree(t)
	f.requireRetirementUnwound(t, round, inst, c, tc.pass)
	next := round
	if tc.atRD {
		next = f.round(t, limits, 0, 1)
		f.refused(t, next, context.Background(), 1, 1, errImageAssignmentCurrent)
		f.clock.add(time.Nanosecond)
	}
	following := f.admitted(t, next, nextCtx, 1, 1, 1)
	f.requireEnd(t, inst, errImageExpired, "unwound instance after the next request")
	held, svc := weak.Make(inst), weak.Make(f.s)
	runtime.GC()
	require(t, held.Value() == nil, "unwound instance reachable through its context after retirement")
	runtime.KeepAlive(c)
	if !tc.atRD {
		f.requireUsage(t, round, 1, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 2, 2, 0), "after the second session admits the same start")
	}
	if !tc.pass {
		f.releaseUnwindWriteMu(t)
	}
	f.requireFault(t, 0, 0, "", "after the stop unwind")
	requireEqual(t, nextCtx.endAndRun(errImageRequestEnd), 1, "following request context functions")
	imageSpin(t, func() bool { ended, _ := f.ended(following); return ended }, "retirement of the following request")
	f.requireEnd(t, following, errImageRequestEnd, "following request after its context ends")
	requireReturned(t, lifecycleClose(f.s), "Close")
	return func() bool {
		runtime.GC()
		released := svc.Value() == nil
		runtime.KeepAlive(c)
		return released
	}
}

func (f *imageTestFixture) unwindRetirement(t *testing.T, round *ImageRound, ctx context.Context, end time.Time, pass bool) *imageInstance {
	t.Helper()
	if pass {
		inst := f.admitted(t, round, ctx, 0, 1, 1)
		f.clock.set(end)
		requireImageUnwindReport(t, f.goRecovered(round, t.Context(), 1, 2), false)
		return inst
	}
	f.peers[0].writeMu.Lock()
	unwound := f.goRecovered(round, ctx, 0, 1)
	f.waitAdmitted(t, 0, 1, "request waiting for writeMu")
	inst := f.instance(1)
	f.clock.set(end)
	requireImageUnwindReport(t, unwound, false)
	return inst
}

func (c *imageHookCtx) unwindFunctionCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.funcs)
}

func (f *imageTestFixture) requireRetirementUnwound(t *testing.T, round *ImageRound, inst *imageInstance, c *imageHookCtx, pass bool) {
	t.Helper()
	f.requireUnwindInstance(t, round, inst)
	requireEqual(t, f.lastID(0), uint64(1), "last request ID on the unwound session")
	if pass {
		requireEqual(t, f.lastID(1), uint64(0), "last request ID of the admission that unwound")
	}
	requireEqual(t, c.unwindFunctionCount(), 1, "registered functions after the stop call unwound")
}

func (f *imageTestFixture) releaseUnwindWriteMu(t *testing.T) {
	t.Helper()
	p := f.peers[0]
	if p.writeMu.TryLock() {
		p.writeMu.Unlock()
		t.Fatal("writeMu was released while the test held it")
	}
	p.writeMu.Unlock()
}

func testImageUnwindRoundEnd(t *testing.T) {
	f := newImageTestFixture(t, 1)
	c, roundCtx := newImageHookCtx(), newImageHookCtx()
	c.onStop = imageUnwinder(false)
	round := f.roundCtx(t, roundCtx, imageUnwindLimits(24*time.Hour, 48*time.Hour), 0)
	inst := f.unwindRetirement(t, round, c, f.clock.Now().Add(24*time.Hour+time.Nanosecond), false)
	f.requireRequesterFree(t)
	f.requireRetirementUnwound(t, round, inst, c, false)
	requireEqual(t, roundCtx.endAndRun(errImageRoundEnd), 1, "round context functions")
	imageSpin(t, func() bool { retired, _ := f.ended(inst); return retired }, "retirement by the round context")
	f.requireEnd(t, inst, errImageRoundEnd, "unwound instance after its round context ends")
	f.releaseUnwindWriteMu(t)
	f.requireFault(t, 0, 0, "", "after the stop unwind")
	requireReturned(t, lifecycleClose(f.s), "Close")
}

func testImageUnwindTimerEnd(t *testing.T) {
	f := newImageTestFixture(t, 1)
	c := newImageHookCtx()
	c.onStop = imageUnwinder(false)
	round := f.round(t, imageUnwindLimits(2*time.Second, 48*time.Hour), 0)
	end, started := f.clock.Now().Add(2*time.Second+time.Nanosecond), time.Now()
	inst := f.unwindRetirement(t, round, c, end, false)
	require(t, time.Since(started) < 2*time.Second, "unwind report arrived after %s, want less than 2s", time.Since(started))
	f.requireRequesterFree(t)
	deadline := time.Now().Add(lifecycleWatchdog)
	for {
		retired, _ := f.ended(inst)
		if retired {
			break
		}
		require(t, time.Now().Before(deadline), "deadline timer did not retire the unwound request within %s", lifecycleWatchdog)
		time.Sleep(time.Millisecond)
	}
	f.requireEnd(t, inst, errImageExpired, "unwound instance after its deadline timer")
	f.releaseUnwindWriteMu(t)
	f.requireFault(t, 0, 0, "", "after the stop unwind")
	requireReturned(t, lifecycleClose(f.s), "Close")
}

type imageFailedWriteUnwindCase struct {
	name             string
	goexit, roundCtx bool
	skip, holder     int
}

func testImageFailedWriteUnwinds(t *testing.T) {
	for _, tc := range []imageFailedWriteUnwindCase{
		{name: "request stop panic after a failed payload write", skip: 1, holder: -1},
		{name: "request stop Goexit after a failed payload write", goexit: true, skip: 1, holder: -1},
		{name: "round stop panic after a failed payload write", roundCtx: true, skip: 1, holder: -1},
		{name: "request stop panic after a failed header write", holder: -1},
		{name: "failed write unwind with bytes held on another session", skip: 1, holder: 1},
		{name: "failed write unwind with bytes held on its session", skip: 1, holder: 0},
	} {
		t.Run(tc.name, func(t *testing.T) { testImageUnwindAfterFailedWrite(t, tc) })
	}
}

func testImageUnwindAfterFailedWrite(t *testing.T, tc imageFailedWriteUnwindCase) {
	f, limits := newImageTestFixture(t, 2), imageUnwindLimits(24*time.Hour, 48*time.Hour)
	if tc.holder >= 0 {
		limits = imageTestLimits(24*time.Hour, 48*time.Hour)
		limits.Global.PendingNetworkBytes = 240
	}
	c := newImageHookCtx()
	c.onStop = imageUnwinder(tc.goexit)
	roundCtx, requestCtx := imageUnwindCtx(c, context.Background(), tc.roundCtx)
	round := f.roundCtx(t, roundCtx, limits, 0, 1)
	leases := f.leases()
	stall := f.wires[0].armStallAfter(tc.skip)
	unwound := f.goRecovered(round, requestCtx, 0, 1)
	requireChannelClosed(t, stall.entered, "failed write of the unwinding request")
	inst := f.instance(1)
	var stallB *imageStall
	var heldB <-chan imageResult
	if tc.holder >= 0 {
		stallB = f.wires[tc.holder].armStallAfter(0)
		heldB = f.goRequest(round, t.Context(), tc.holder, 2)
		f.waitAdmitted(t, tc.holder, uint64(2-tc.holder), "second holder")
	}
	if tc.holder == 1 {
		requireChannelClosed(t, stallB.entered, "write of the second holder")
	}
	done := make(chan struct{})
	defer close(done)
	var waitWrite <-chan struct{}
	if tc.holder == 0 {
		waitWrite = stallB.entered
	}
	observedClose := f.observeUnwindClose(round, waitWrite, done)
	stall.release <- errImageScriptedWrite
	if tc.holder == 0 {
		requireImageResult(t, awaitImageResult(t, heldB, "second holder"), 2, 2, net.ErrClosed, "second holder")
	}
	requireImageUnwindReport(t, unwound, tc.goexit)
	f.requireRequesterFree(t)
	requireUnwindWritePrefix(t, f.wires[0], tc.skip*wireHeaderSize)
	f.requireFailedUnwindClose(t, observedClose, tc.holder, leases)
	f.finishFailedWriteUnwind(t, round, inst, c, tc.holder, stallB, heldB)
	requireReturned(t, lifecycleClose(f.s), "Close")
}

type imageUnwindClose struct {
	pending   [2]uint64
	leases    uint64
	lastError string
}

func (f *imageTestFixture) observeUnwindClose(round *ImageRound, waitWrite, done <-chan struct{}) <-chan imageUnwindClose {
	observed := make(chan imageUnwindClose, 1)
	f.onClose(0, func() {
		select {
		case <-done:
			return
		default:
		}
		if waitWrite != nil {
			select {
			case <-waitWrite:
			case <-done:
				return
			}
		}
		per, global := f.usage(round, 0)
		observed <- imageUnwindClose{
			pending:   [2]uint64{per[unitPendingNetworkBytes], global[unitPendingNetworkBytes]},
			leases:    f.leases(),
			lastError: f.fault(0).lastError,
		}
	})
	return observed
}

func (f *imageTestFixture) requireFailedUnwindClose(t *testing.T, observed <-chan imageUnwindClose, holder int, leases uint64) {
	t.Helper()
	closes, lastError, lastID := 1, errImageScriptedWrite.Error(), uint64(1)
	want := imageUnwindClose{leases: leases + 1, lastError: errImageScriptedWrite.Error()}
	if holder >= 0 {
		want.pending[1] = 120
		want.leases++
	}
	if holder == 0 {
		closes, lastError, lastID = 2, net.ErrClosed.Error(), 2
		want.pending[0] = 120
	}
	f.requireFault(t, 0, closes, lastError, "after the failed write unwind")
	got := awaitImageResult(t, observed, "snapshot in the close hook")
	requireEqual(t, got.pending, want.pending, "pending bytes on the closing session and globally")
	requireEqual(t, got.leases, want.leases, "Service leases in the close hook")
	requireEqual(t, got.lastError, want.lastError, "last error in the first close hook")
	require(t, f.peers[0].writeMu.TryLock(), "writeMu still held after the failed write unwind")
	f.peers[0].writeMu.Unlock()
	requireEqual(t, f.lastID(0), lastID, "last request ID on the closing session")
}

func (f *imageTestFixture) finishFailedWriteUnwind(t *testing.T, round *ImageRound, inst *imageInstance, c *imageHookCtx, holder int, stallB *imageStall, heldB <-chan imageResult) {
	t.Helper()
	current, nextID := uint64(1), uint64(1)
	if holder == 1 {
		nextC := f.goRequest(round, t.Context(), 1, 3)
		f.waitAdmitted(t, 1, 2, "request at the global limit")
		f.refused(t, round, context.Background(), 1, 4, errImageLimit)
		stallB.release <- nil
		requireImageResult(t, awaitImageResult(t, heldB, "second holder"), 1, 2, nil, "second holder")
		requireImageResult(t, awaitImageResult(t, nextC, "request at the global limit"), 2, 3, nil, "request at the global limit")
		current, nextID = 3, 3
	}
	f.requireCurrentAfterUnwind(t, round, inst, [2]uint64{1, current})
	requireEqual(t, c.unwindFunctionCount(), 1, "registered functions after the failed write unwind")
	f.refused(t, round, context.Background(), 1, 1, errImageAssignmentCurrent)
	if holder == 0 {
		per, global := f.usage(round, 0)
		requireEqual(t, [2]uint64{per[unitPendingNetworkBytes], global[unitPendingNetworkBytes]}, [2]uint64{}, "pending bytes on the closing session and globally after the next request")
		return
	}
	f.clock.add(24*time.Hour + time.Nanosecond)
	f.admitted(t, round, context.Background(), 1, 1, nextID)
	f.requireEnd(t, inst, errImageExpired, "failed write instance after the next admission")
}
