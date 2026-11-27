package p2p

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"weak"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestImageRequesterLifetime(t *testing.T) {
	t.Run("round admission clock section", testImageRoundAdmissionClock)
	t.Run("local ends", testImageLocalEnds)
	t.Run("receive order", inImageBubble(testImageReceiveOrder))
	t.Run("competing receivers", inImageBubble(testImageCompetingReceivers))
	t.Run("wait context", inImageBubble(testImageReceiveWaitContext))
	t.Run("end before write", testImageTerminalEndBeforeWrite)
	t.Run("recorded end across adapter", testImageRecordedEndAcrossAdapter)
	t.Run("end during authorized write", testImageEndAtActualWrite)
	t.Run("staged order", testImageStagedOrder)
	t.Run("write unwind precedes end", testImageUnwindThenEnd)
	t.Run("pending capacity", inImageBubble(testImageOutcomePendingCapacity))
	t.Run("first write error", testImageFirstWriteError)
	t.Run("round close", inImageBubble(testImageRoundOutcomeClose))
	t.Run("service close", testImageServiceOutcomeClose)
	t.Run("leased receive", testImageLeasedReceive)
	t.Run("passive receive during join", testImagePassiveReceiveJoin)
	t.Run("exact registration", testImageExitAtQuota)
	t.Run("registration exit before retry join", testImageExitBeforeRetryJoin)
	t.Run("announcement exit before diagnostics", testImageAnnouncementExitBeforePublish)
	t.Run("read exit before diagnostics", testImageReadExitBeforePublish)
	t.Run("transport diagnostics during retirement unwind", testImageTransportExitUnwind)
	t.Run("first exit with live replacement", testImageExitWithLiveReplacement)
	t.Run("same address replacement", testImageReplacementRetainsNoPeer)
	t.Run("exit before first capture", testImageExitBeforeCapture)
	t.Run("retirement between snapshot and capture", testImageRetirementBetweenSnapshotAndCapture)
	t.Run("retired source refusal allocations", testImageRetiredSourceAllocations)
	t.Run("source bound counts live aliases", testImageLiveSourceBound)
	t.Run("terminal context hooks", testImageTerminalHooks)
	t.Run("terminal observation unwind", testImageTerminalObservationUnwind)
	t.Run("caller context after service close", testImageTerminalServiceRetention)
	t.Run("probe deadlines", testImageProbeDeadlines)
	t.Run("probe constructor refusals", testImageProbeConstructor)
	t.Run("probe entry refusals", testImageProbeEntryRefusals)
	t.Run("terminal entry precedence", testImageTerminalEntryPriority)
	t.Run("early refusals preserve a due assignment", testImageEarlyRefusalPreservesEnd)
	t.Run("probe draining", testImageProbeDrain)
	t.Run("probe presend deadlines", testImageProbeBeforeWrite)
}

func testImageRoundAdmissionClock(t *testing.T) {
	f := newImageTestFixture(t, 1)
	base := f.clock.add(0)
	reads := f.clock.readCount()
	config := f.config(imageTestLimits(2*time.Second, 5*time.Second), 0)
	entered, release := f.blockNextRead(func(now time.Time) time.Time { return now }, func() {})
	defer release()
	begin := make(chan imageBegin, 1)
	go func() {
		round, err := f.s.BeginImageRound(t.Context(), config)
		begin <- imageBegin{round: round, err: err}
	}()
	requireChannelClosed(t, entered, "actual round admission clock read")
	mu := &f.s.imageRequester.mu
	if mu.TryLock() {
		mu.Unlock()
		t.Fatal("round admission clock read outside the requester lock")
	}
	release()
	got := awaitImageResult(t, begin, "round admission after clock release")
	must(t, got.err, "round admission after clock release")
	requireEqual(t, f.clock.readCount(), reads+1, "round admission clock reads")
	f.clock.set(base.Add(5*time.Second - 1))
	f.admitted(t, got.round, t.Context(), 0, 1, 1)
	f.requireFrames(t, 0, "frame before captured round cutoff", expectedImageQuery(1, 1))
}

func takeImage(round *ImageRound, ctx context.Context, start byte) imageResult {
	result, err := round.Receive(ctx, imageStart(start))
	return imageResult{result.Query, err}
}

func goTakeImage(round *ImageRound, ctx context.Context, start byte) <-chan imageResult {
	out := make(chan imageResult, 1)
	go func() { out <- takeImage(round, ctx, start) }()
	return out
}

func requireImageTake(t *testing.T, round *ImageRound, ctx context.Context, start byte, q consensus.UTXOImageQuery, want error, label string) {
	t.Helper()
	got := awaitImageResult(t, goTakeImage(round, ctx, start), label)
	requireQueryResult(t, got, q, want, label)
	if slices.Contains([]error{errImageNoAssignment, errImageRoundClosed, errImageDisconnected}, want) {
		var single interface{ Unwrap() error }
		var multiple interface{ Unwrap() []error }
		if errors.As(got.err, &single) || errors.As(got.err, &multiple) {
			t.Fatalf("%s returned a receive error with Unwrap: %v", label, got.err)
		}
	}
}

func requireImageAbsent(t *testing.T, round *ImageRound, ctx context.Context, start byte, want error) {
	t.Helper()
	requireImageTake(t, round, ctx, start, consensus.UTXOImageQuery{}, want, "receive without a result")
}

func requireImageWaiting(t *testing.T, done <-chan imageResult, label string) {
	t.Helper()
	select {
	case got := <-done:
		t.Fatalf("%s: Receive returned %+v while its assignment was pending", label, got)
	default:
	}
}

type imageLocalEndCase struct {
	name   string
	want   error
	capD   bool
	follow bool
	wait   bool
	end    func(*testing.T, *imageTestFixture, *imageHookCtx, *imageHookCtx, time.Time)
}

func testImageLocalEnds(t *testing.T) {
	for _, tc := range []imageLocalEndCase{
		{name: "request ctx", want: errImageRequestEnd, follow: true, wait: true, end: endImageRequestCtx},
		{name: "round ctx", want: errImageRoundEnd, wait: true, end: endImageRoundCtx},
		{name: "timer past D", want: errImageExpired, follow: true, wait: true, end: endImageTimer},
		{name: "receive after capped D", want: errImageExpired, capD: true, end: endImageAfterSpentTimer},
		{name: "session exit", want: errImageDisconnected, end: endImageSession},
		{name: "independent request pass", want: errImageExpired, follow: true, end: endImageRequestPass},
	} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) { checkImageLocalEnd(t, tc) }))
	}
	t.Run("independent receive pass", inImageBubble(testImageIndependentReceivePass))
}

func checkImageLocalEnd(t *testing.T, tc imageLocalEndCase) {
	f := newImageTestFixture(t, 2)
	limits := imageTestLimits(10*time.Second, time.Hour)
	if tc.capD {
		limits.RoundLifetime = 5 * time.Second
	}
	disconnected := errors.Is(tc.want, errImageDisconnected)
	if disconnected {
		limits.Global.CurrentAssignments = 1
		limits.Global.AdmittedRequests = 2
	}
	ctx, owner := newImageHookCtx(), newImageHookCtx()
	round := f.roundCtx(t, owner, limits, 0, 1)
	inst := f.admitted(t, round, ctx, 0, 1, 1)
	var passive <-chan imageResult
	if tc.wait {
		passive = goTakeImage(round, t.Context(), 1)
		synctest.Wait()
		requireImageWaiting(t, passive, "waiter before assignment end")
	}
	tc.end(t, f, ctx, owner, inst.deadline)
	if passive == nil {
		passive = goTakeImage(round, t.Context(), 1)
	}
	requireImageResult(t, awaitImageResult(t, passive, "recorded local end"), 1, 1, tc.want, "recorded local end")
	requireImageAbsent(t, round, t.Context(), 1, errImageNoAssignment)
	if disconnected {
		successorCtx := newImageHookCtx()
		requireImageResult(t, f.request(round, successorCtx, 1, 1), 1, 1, nil, "same start on live source after disconnect")
		requireQueryResult(t, f.request(round, t.Context(), 0, 1), consensus.UTXOImageQuery{}, errImageDisconnected, "same start on disconnected source")
		successorCtx.end(context.Canceled)
		requireImageTake(t, round, t.Context(), 1, expectedImageQuery(1, 1), context.Canceled, "ended request on live source")
		requireQueryResult(t, f.request(round, t.Context(), 1, 2), consensus.UTXOImageQuery{}, errImageLimit, "unused start after two admitted requests")
	} else if tc.follow {
		f.refused(t, round, t.Context(), 0, 1, errImageAttempted)
		nextID := uint64(1)
		if tc.name == "independent request pass" {
			nextID = 2
		}
		f.admitted(t, round, t.Context(), 1, 1, nextID)
	}
	f.requireFrames(t, 0, "ended assignment", expectedImageQuery(1, 1))
}

func endImageRequestCtx(t *testing.T, _ *imageTestFixture, ctx, _ *imageHookCtx, _ time.Time) {
	requireEqual(t, ctx.endAndRun(errImageRequestEnd), 1, "request callback count")
}

func endImageRoundCtx(t *testing.T, _ *imageTestFixture, _, owner *imageHookCtx, _ time.Time) {
	requireEqual(t, owner.endAndRun(errImageRoundEnd), 1, "round callback count")
}

func endImageTimer(_ *testing.T, f *imageTestFixture, _, _ *imageHookCtx, deadline time.Time) {
	f.clock.set(deadline.Add(1))
	time.Sleep(10*time.Second + 1)
	synctest.Wait()
}

func endImageAfterSpentTimer(t *testing.T, f *imageTestFixture, _, _ *imageHookCtx, deadline time.Time) {
	reads := f.clock.readCount()
	time.Sleep(5*time.Second + 1)
	synctest.Wait()
	requireEqual(t, f.clock.readCount(), reads+1, "spent timer clock read")
	f.clock.set(deadline.Add(1))
}

func endImageSession(_ *testing.T, f *imageTestFixture, _, _ *imageHookCtx, _ time.Time) {
	f.s.unregisterPeer(f.peers[0])
}

func endImageRequestPass(t *testing.T, f *imageTestFixture, _, _ *imageHookCtx, deadline time.Time) {
	f.clock.set(deadline.Add(1))
	other := f.round(t, imageTestLimits(), 1)
	ctx := newImageHookCtx()
	f.admitted(t, other, ctx, 1, 1, 1)
	ctx.endAndRun(errImageRequestEnd)
	synctest.Wait()
}

func testImageIndependentReceivePass(t *testing.T) {
	f, original := newImageRound(t, 2, 0)
	other := f.round(t, imageTestLimits(), 1)
	ctx := newImageHookCtx()
	inst := f.admitTimerSpent(t, original, ctx, 0, 1, 1)
	f.clock.set(inst.deadline.Add(time.Nanosecond))
	requireImageAbsent(t, other, t.Context(), 2, errImageNoAssignment)
	ctx.end(context.Canceled)
	requireImageTake(t, original, t.Context(), 1, expectedImageQuery(1, 1), errImageExpired, "expiration recorded by another round's Receive")
	requireImageAbsent(t, original, t.Context(), 1, errImageNoAssignment)
}

func testImageReceiveOrder(t *testing.T) {
	f, round := newImageRound(t, 2, 0, 1)
	a, b, sibling := newImageHookCtx(), newImageHookCtx(), newImageHookCtx()
	first, second, unrelated := expectedImageQuery(1, 1), expectedImageQuery(1, 1), expectedImageQuery(2, 2)
	second.ByteLimit++
	f.admitted(t, round, a, 0, 1, 1)
	a.endAndRun(errImageRequestEnd)
	synctest.Wait()
	requireQueryResult(t, awaitImageResult(t, launch(round, b, f.ids[1], 1, second.ByteLimit), "second send"), second, nil, "second send")
	b.endAndRun(errImageRoundEnd)
	synctest.Wait()
	f.admitted(t, round, sibling, 0, 2, 2)
	sibling.endAndRun(context.Canceled)
	synctest.Wait()
	copyOfRound := *round
	other := f.round(t, imageTestLimits(), 0)
	*round = *other
	requireImageAbsent(t, round, t.Context(), 1, errImageNoAssignment)
	requireImageTake(t, &copyOfRound, t.Context(), 1, first, errImageRequestEnd, "first admitted result")
	requireImageTake(t, &copyOfRound, t.Context(), 1, second, errImageRoundEnd, "second admitted result")
	requireImageAbsent(t, &copyOfRound, t.Context(), 1, errImageNoAssignment)
	requireImageTake(t, &copyOfRound, t.Context(), 2, unrelated, context.Canceled, "unrelated start's result")
	requireImageResult(t, f.request(round, t.Context(), 0, 1), 3, 1, nil, "independent round request")

	waitCtx, cancelWait := context.WithCancel(t.Context())
	cancelWait()
	result, err := copyOfRound.Receive(waitCtx, imageStart(1))
	requireEqual(t, err, errImageNoAssignment, "previous round receive error for a reassigned start")
	requireEqual(t, result, ImageResult{}, "previous round receive result")
	result, err = round.Receive(waitCtx, imageStart(1))
	requireEqual(t, err, context.Canceled, "current round receive error")
	requireEqual(t, result, ImageResult{}, "current round receive result")

	f.requireUsage(t, &copyOfRound, 0, imageUsage(0, 2, 2, 2, 0), imageUsage(0, 2, 3, 3, 0), "original round after handle reassignment")
	f.requireUsage(t, round, 0, imageUsage(1, 1, 1, 1, 0), imageUsage(1, 1, 1, 1, 0), "independent round")
}

func testImageCompetingReceivers(t *testing.T) {
	f, round := newImageRound(t, 1, 0)
	ctx := newImageHookCtx()
	f.admitted(t, round, ctx, 0, 1, 1)
	a, b := goTakeImage(round, t.Context(), 1), goTakeImage(round, t.Context(), 1)
	synctest.Wait()
	requireImageWaiting(t, a, "first waiter")
	requireImageWaiting(t, b, "second waiter")
	other := f.round(t, imageTestLimits(), 0)
	*round = *other
	ctx.endAndRun(errImageRequestEnd)
	one, two := awaitImageResult(t, a, "first waiter"), awaitImageResult(t, b, "second waiter")
	if errors.Is(one.err, errImageNoAssignment) {
		one, two = two, one
	}
	requireImageResult(t, one, 1, 1, errImageRequestEnd, "successful take")
	requireQueryResult(t, two, consensus.UTXOImageQuery{}, errImageNoAssignment, "competing take")
}

func testImageReceiveWaitContext(t *testing.T) {
	f, round := newImageRound(t, 2, 0, 1)
	ctx := newImageHookCtx()
	f.admitted(t, round, ctx, 0, 1, 1)
	waitCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waiting := goTakeImage(round, waitCtx, 1)
	synctest.Wait()
	requireImageWaiting(t, waiting, "live waiter")
	reads := f.clock.readCount()
	time.Sleep(250 * time.Millisecond)
	synctest.Wait()
	requireEqual(t, f.clock.readCount(), reads, "clock reads while Receive waits")
	cancel()
	requireQueryResult(t, awaitImageResult(t, waiting, "canceled waiter"), consensus.UTXOImageQuery{}, context.Canceled, "canceled waiter")
	f.refused(t, round, t.Context(), 1, 1, errImageAssignmentCurrent)
	ctx.endAndRun(errImageRequestEnd)
	synctest.Wait()
	requireImageTake(t, round, waitCtx, 1, expectedImageQuery(1, 1), errImageRequestEnd, "ready result with canceled waiter")
	requireImageAbsent(t, round, waitCtx, 1, errImageNoAssignment)
	f.admitted(t, round, t.Context(), 1, 1, 1)
}

type imageTerminalEndCase struct {
	name         string
	requestErr   error
	roundErr     error
	expired      bool
	adapterClose bool
	ordinary     bool
	want         error
}

func testImageTerminalEndBeforeWrite(t *testing.T) {
	for _, tc := range []imageTerminalEndCase{
		{name: "disconnect", want: errImageDisconnected},
		{name: "request ctx before disconnect", requestErr: errImageRequestEnd, roundErr: errImageRoundEnd, expired: true, want: errImageRequestEnd},
		{name: "round ctx before disconnect", roundErr: errImageRoundEnd, expired: true, want: errImageRoundEnd},
		{name: "expiry before disconnect", expired: true, want: errImageExpired},
		{name: "explicit close", adapterClose: true, want: errImageRoundClosed},
		{name: "request ctx before close", adapterClose: true, requestErr: errImageRequestEnd, roundErr: errImageRoundEnd, expired: true, want: errImageRequestEnd},
		{name: "round ctx before close", adapterClose: true, roundErr: errImageRoundEnd, expired: true, want: errImageRoundEnd},
		{name: "expiry before close", adapterClose: true, expired: true, want: errImageExpired},
		{name: "request ctx while queued", ordinary: true, requestErr: errImageRequestEnd, want: errImageRequestEnd},
		{name: "round ctx while queued", ordinary: true, roundErr: errImageRoundEnd, want: errImageRoundEnd},
		{name: "expiry while queued", ordinary: true, expired: true, want: errImageExpired},
	} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) { checkImageTerminalEndBeforeWrite(t, tc) }))
	}
	t.Run("recorded end skips clock", testImageRecordedEndSkipsPreWriteClock)
}

func checkImageTerminalEndBeforeWrite(t *testing.T, tc imageTerminalEndCase) {
	f := newImageTestFixture(t, 2)
	owner, ctx := newImageHookCtx(), newImageHookCtx()
	round := f.roundCtx(t, owner, imageTestLimits(), 0)
	replacement := f.round(t, imageTestLimits(), 1)
	release := f.holdWrite(t, 0)
	pending := f.goRequest(round, ctx, 0, 1)
	synctest.Wait()
	f.waitAdmitted(t, 0, 1, "request waiting for writeMu")
	receive := goTakeImage(round, t.Context(), 1)
	synctest.Wait()
	requireImageWaiting(t, receive, "queued assignment waiter")
	if tc.requestErr != nil {
		ctx.end(tc.requestErr)
	}
	if tc.roundErr != nil {
		owner.end(tc.roundErr)
	}
	if tc.expired {
		f.clock.add(10*time.Second + 1)
	}
	if !tc.ordinary {
		if tc.adapterClose {
			round.Close()
		} else {
			f.s.unregisterPeer(f.peers[0])
		}
	}
	requireImageResult(t, awaitImageResult(t, pending, "request before write"), 1, 1, tc.want, "recorded end before write")
	wantReceive := errImageNoAssignment
	if tc.adapterClose {
		wantReceive = errImageRoundClosed
	}
	requireQueryResult(t, awaitImageResult(t, receive, "waiter on pre-write end"), consensus.UTXOImageQuery{}, wantReceive, "waiter on pre-write end")
	f.admitted(t, replacement, t.Context(), 1, 1, 1)
	must(t, release(), "holder write")
	f.requireFrames(t, 0, "ended before write")
}

func testImageRecordedEndSkipsPreWriteClock(t *testing.T) {
	for _, tc := range []struct {
		terminal string
		end      error
	}{{"round close", errImageRoundClosed}, {"peer exit", errImageDisconnected}} {
		t.Run(tc.terminal, inImageBubble(func(t *testing.T) {
			f, round := newImageRound(t, 1, 0)
			release := f.holdWrite(t, 0)
			defer func() { must(t, release(), "holder write") }()
			pending := f.goRecovered(round, t.Context(), 0, 1)
			f.waitAdmitted(t, 0, 1, "request waiting for writeMu")
			synctest.Wait()
			select {
			case got := <-pending:
				t.Fatalf("parked Request returned before the terminal end: %v", got)
			default:
			}
			applyImageTerminal(f, round, tc.terminal)
			f.unwindAtPreWriteRead(imageUnwinder(true))
			defer f.clock.onNextRead(nil)
			got := awaitImageResult(t, pending, "parked Request after terminal end")
			want := imageResult{q: expectedImageQuery(1, 1), err: tc.end}
			requireEqual(t, got, any(want), "parked Request after terminal end")
			usage := imageUsage(0, 1, 1, 1, 0)
			f.requireUsage(t, round, 0, usage, usage, "parked Request after terminal end")
			f.requireFrames(t, 0, "parked Request after terminal end")
		}))
	}
}

func testImageRecordedEndAcrossAdapter(t *testing.T) {
	inImageBubble(func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		ctx, owner := newImageHookCtx(), newImageHookCtx()
		round := f.roundCtx(t, owner, imageTestLimits(), 0)
		next := f.round(t, imageTestLimits(), 1)
		release := f.holdWrite(t, 0)
		send := f.goRequest(round, ctx, 0, 1)
		synctest.Wait()
		f.waitAdmitted(t, 0, 1, "parked assignment")
		owner.endAndRun(errImageRoundEnd)
		synctest.Wait()
		ctx.end(errImageRequestEnd)
		f.clock.add(10*time.Second + 1)
		round.Close()
		f.s.unregisterPeer(f.peers[0])
		requireImageResult(t, awaitImageResult(t, send, "parked assignment after close and exit"), 1, 1, errImageRoundEnd, "first recorded end")
		f.admitted(t, next, t.Context(), 1, 1, 1)
		requireImageAbsent(t, round, t.Context(), 1, errImageRoundClosed)
		must(t, release(), "holder write")
		f.requireFrames(t, 0, "parked assignment after close and exit")
	})(t)
}

type imageStagedWriteCase struct {
	name   string
	fault  error
	unwind func()
	goexit bool
}

func testImageStagedOrder(t *testing.T) {
	for _, tc := range []imageStagedWriteCase{
		{name: "successful send"},
		{name: "failed send after local end", fault: errImageScriptedWrite},
		{name: "write panic", unwind: imageUnwinder(false)},
		{name: "write Goexit", unwind: imageUnwinder(true), goexit: true},
	} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) { checkImageStagedOrder(t, tc) }))
	}
	t.Run("ready outcome survives later write panic", inImageBubble(testImageReadyOutcomeSurvivesUnwind))
}

func testImageEndAtActualWrite(t *testing.T) {
	for _, local := range []struct {
		name string
		want error
		end  func(*testing.T, *imageTestFixture, *ImageRound, *imageHookCtx, *imageHookCtx)
	}{
		{"request context", errImageRequestEnd, func(_ *testing.T, _ *imageTestFixture, _ *ImageRound, ctx, _ *imageHookCtx) {
			ctx.endAndRun(errImageRequestEnd)
		}},
		{"round context", errImageRoundEnd, func(_ *testing.T, _ *imageTestFixture, _ *ImageRound, _, owner *imageHookCtx) {
			owner.endAndRun(errImageRoundEnd)
		}},
		{"elapsed attempt", errImageExpired, func(_ *testing.T, f *imageTestFixture, _ *ImageRound, _, _ *imageHookCtx) {
			f.clock.add(10*time.Second + 1)
		}},
		{"exact peer exit", errImageDisconnected, func(_ *testing.T, f *imageTestFixture, _ *ImageRound, _, _ *imageHookCtx) {
			f.s.unregisterPeer(f.peers[0])
		}},
		{"explicit round close", errImageRoundClosed, func(_ *testing.T, _ *imageTestFixture, round *ImageRound, _, _ *imageHookCtx) {
			round.Close()
		}},
	} {
		t.Run(local.name, func(t *testing.T) {
			for _, fault := range []struct {
				name string
				err  error
			}{{"nil write result", nil}, {"transport error", errImageScriptedWrite}} {
				t.Run(fault.name, inImageBubble(func(t *testing.T) {
					checkImageEndAtActualWrite(t, local.want, local.end, fault.err)
				}))
			}
		})
	}
}

func checkImageEndAtActualWrite(t *testing.T, want error, end func(*testing.T, *imageTestFixture, *ImageRound, *imageHookCtx, *imageHookCtx), fault error) {
	f := newImageTestFixture(t, 1)
	ctx, owner := newImageHookCtx(), newImageHookCtx()
	round := f.roundCtx(t, owner, imageTestLimits(), 0)
	writing, pending := f.stalledRequest(t, round, ctx, 0, 1)
	defer close(writing.release)
	end(t, f, round, ctx, owner)
	synctest.Wait()
	waitCtx, cancel := context.WithCancel(t.Context())
	cancel()
	wantBlocked := error(context.Canceled)
	if errors.Is(want, errImageRoundClosed) {
		wantBlocked = errImageRoundClosed
	}
	requireImageAbsent(t, round, waitCtx, 1, wantBlocked)
	writing.release <- fault
	requireImageResult(t, awaitImageResult(t, pending, "authorized write result"), 1, 1, nil, "authorized write result")
	if errors.Is(want, errImageRoundClosed) {
		requireImageAbsent(t, round, t.Context(), 1, errImageRoundClosed)
	} else {
		requireImageTake(t, round, t.Context(), 1, expectedImageQuery(1, 1), want, "single ended result")
		requireImageAbsent(t, round, t.Context(), 1, errImageNoAssignment)
	}
	if fault != nil {
		f.requireFault(t, 0, 1, fault.Error(), "actual write fault behind the recorded end")
	}
}

// holdImageFrame pauses the connection before accepting the first frame byte.
func (f *imageTestFixture) holdImageFrame(t *testing.T, session int, finish func()) (<-chan struct{}, func()) {
	t.Helper()
	entered, gate := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	conn, wire := f.conns[session], f.wires[session]
	var once sync.Once
	conn.mu.Lock()
	conn.writeHook = func(b []byte) (int, error) {
		once.Do(func() { close(entered); <-gate; finish() })
		return wire.write(b)
	}
	conn.mu.Unlock()
	return entered, release
}

func (f *imageTestFixture) beginStagedWrite(t *testing.T, round *ImageRound, ctx context.Context, tc imageStagedWriteCase) (<-chan any, func()) {
	t.Helper()
	if tc.unwind != nil {
		entered, release := f.holdImageFrame(t, 0, tc.unwind)
		writing := f.goRecovered(round, ctx, 0, 1)
		requireChannelClosed(t, entered, "authorized write")
		return writing, release
	}
	stall := f.wires[0].armStallAfter(0)
	writing := f.goRecovered(round, ctx, 0, 1)
	requireChannelClosed(t, stall.entered, "authorized write")
	release := sync.OnceFunc(func() { stall.release <- tc.fault })
	t.Cleanup(release)
	return writing, release
}

func checkImageStagedOrder(t *testing.T, tc imageStagedWriteCase) {
	f := newImageTestFixture(t, 3)
	limits := imageTestLimits()
	limits.Global.PendingNetworkBytes = 240
	round := f.round(t, limits, 0, 1, 2)
	first, second := newImageHookCtx(), newImageHookCtx()
	write, release := f.beginStagedWrite(t, round, first, tc)
	defer release()
	first.endAndRun(errImageRequestEnd)
	synctest.Wait()
	q1, q2 := expectedImageQuery(1, 1), expectedImageQuery(1, 1)
	q2.ByteLimit++
	requireQueryResult(t, awaitImageResult(t, launch(round, second, f.ids[1], 1, q2.ByteLimit), "second send"), q2, nil, "second send")
	second.endAndRun(errImageRoundEnd)
	synctest.Wait()
	var checkCapacity func()
	if tc.unwind != nil {
		checkCapacity = f.holdImageUnwindSibling(t, round)
	}
	take := goTakeImage(round, t.Context(), 1)
	synctest.Wait()
	requireImageWaiting(t, take, "earlier write awaiting its return")
	release()
	returned := awaitImageResult(t, write, "first send verdict")
	if tc.unwind != nil {
		requireImageUnwindValue(t, returned, tc.goexit)
		requireQueryResult(t, awaitImageResult(t, take, "first take after unwind"), q2, errImageRoundEnd, "first take after unwind")
	} else {
		requireEqual(t, returned, any(imageResult{q: q1}), "first send result")
		requireQueryResult(t, awaitImageResult(t, take, "first take after send"), q1, errImageRequestEnd, "first take after send")
		requireImageTake(t, round, t.Context(), 1, q2, errImageRoundEnd, "second take after send")
	}
	requireImageAbsent(t, round, t.Context(), 1, errImageNoAssignment)
	if checkCapacity != nil {
		checkCapacity()
	}
	if tc.fault != nil {
		f.requireFault(t, 0, 1, tc.fault.Error(), "actual write fault behind the recorded end")
	}
}

func testImageReadyOutcomeSurvivesUnwind(t *testing.T) {
	f, round := newImageRound(t, 2, 0, 1)
	ready, writing := newImageHookCtx(), newImageHookCtx()
	q := expectedImageQuery(1, 1)
	q.ByteLimit++
	sent := launch(round, ready, f.ids[1], 1, q.ByteLimit)
	requireQueryResult(t, awaitImageResult(t, sent, "older send"), q, nil, "older send")
	requireEqual(t, ready.endAndRun(errImageRoundEnd), 1, "older request callback count")
	write, release := f.beginStagedWrite(t, round, writing, imageStagedWriteCase{unwind: imageUnwinder(false)})
	defer release()
	requireEqual(t, writing.endAndRun(errImageRequestEnd), 1, "writing request callback count")
	synctest.Wait()
	release()
	requireImageUnwindReport(t, write, false)
	waitCtx, cancel := context.WithCancel(t.Context())
	cancel()
	requireImageTake(t, round, waitCtx, 1, q, errImageRoundEnd, "older ready outcome after later write panic")
	requireImageAbsent(t, round, waitCtx, 1, errImageNoAssignment)
}

func (f *imageTestFixture) holdImageUnwindSibling(t *testing.T, round *ImageRound) func() {
	t.Helper()
	stall, pending := f.stalledRequest(t, round, t.Context(), 2, 3)
	release := sync.OnceFunc(func() { stall.release <- nil })
	t.Cleanup(release)
	requireQueryResult(t, f.request(round, t.Context(), 1, 4), consensus.UTXOImageQuery{}, errImageLimit, "capacity held by both active writers")
	return func() {
		f.admitted(t, round, t.Context(), 1, 4, 2)
		release()
		requireImageResult(t, awaitImageResult(t, pending, "sibling send"), 1, 3, nil, "sibling send")
	}
}

func testImageUnwindThenEnd(t *testing.T) {
	for _, tc := range []struct {
		name   string
		goexit bool
	}{{"panic", false}, {"Goexit", true}} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f, round := newImageRound(t, 2, 0, 1)
			ctx := newImageHookCtx()
			write, release := f.beginStagedWrite(t, round, ctx, imageStagedWriteCase{unwind: imageUnwinder(tc.goexit)})
			release()
			requireImageUnwindReport(t, write, tc.goexit)
			f.refused(t, round, t.Context(), 1, 1, errImageAssignmentCurrent)
			ctx.endAndRun(errImageRequestEnd)
			synctest.Wait()
			requireImageAbsent(t, round, t.Context(), 1, errImageNoAssignment)
			f.admitted(t, round, t.Context(), 1, 1, 1)
		}))
	}
}

func testImageOutcomePendingCapacity(t *testing.T) {
	f := newImageTestFixture(t, 3)
	limits := imageTestLimits()
	limits.Global.PendingNetworkBytes = 240
	round := f.round(t, limits, 0, 1, 2)
	a, waitDone := newImageHookCtx(), t.Context()
	stallA, pendingA := f.stalledRequest(t, round, a, 0, 1)
	stallB, pendingB := f.stalledRequest(t, round, waitDone, 1, 2)
	defer close(stallA.release)
	defer close(stallB.release)
	a.endAndRun(errImageRequestEnd)
	synctest.Wait()
	f.refused(t, round, waitDone, 2, 3, errImageLimit)
	stallA.release <- nil
	requireImageResult(t, awaitImageResult(t, pendingA, "first send"), 1, 1, nil, "first send")
	stallC, pendingC := f.stalledRequest(t, round, waitDone, 2, 3)
	defer close(stallC.release)
	f.refused(t, round, waitDone, 0, 4, errImageLimit)
	stallB.release <- nil
	requireImageResult(t, awaitImageResult(t, pendingB, "sibling send"), 1, 2, nil, "sibling send")
	f.admitted(t, round, waitDone, 0, 4, 2)
	stallC.release <- nil
	requireImageResult(t, awaitImageResult(t, pendingC, "third send"), 1, 3, nil, "third send")
	requireImageTake(t, round, waitDone, 1, expectedImageQuery(1, 1), errImageRequestEnd, "first write's end")
}

func testImageFirstWriteError(t *testing.T) {
	f, round := newImageRound(t, 2, 0, 1)
	ctx := t.Context()
	f.admitted(t, round, ctx, 0, 2, 1)
	wait, cancel := context.WithCancel(ctx)
	cancel()
	closer, outcome := make(chan imageResult, 1), make(chan imageResult, 1)
	f.onClose(0, func() {
		if imageCalledFrom(".(*ImageRound).Request") {
			outcome <- takeImage(round, wait, 1)
			q, err := round.Request(ctx, f.ids[1], imageStart(1), imageTestByteLimit)
			closer <- imageResult{q, err}
		}
	})
	stall, pending := f.stalledRequest(t, round, ctx, 0, 1)
	stall.release <- errImageScriptedWrite
	requireImageResult(t, awaitImageResult(t, pending, "failed write"), 2, 1, errImageScriptedWrite, "failed write")
	requireQueryResult(t, awaitImageResult(t, outcome, "Receive in Close hook"), consensus.UTXOImageQuery{}, errImageNoAssignment, "failed write Receive in Close hook")
	requireImageResult(t, awaitImageResult(t, closer, "replacement in Close hook"), 1, 1, nil, "replacement in Close hook")
	requireImageAbsent(t, round, wait, 1, context.Canceled)
	other := f.round(t, imageTestLimits(), 1)
	f.refused(t, other, ctx, 1, 2, errImageAssignmentCurrent)
	f.s.unregisterPeer(f.peers[0])
	requireImageTake(t, round, ctx, 2, expectedImageQuery(1, 2), errImageDisconnected, "sibling ends at session exit")
	requireImageAbsent(t, round, ctx, 2, errImageNoAssignment)
	f.s.unregisterPeer(f.peers[0])
	requireImageAbsent(t, round, wait, 1, context.Canceled)
	f.requireFault(t, 0, 1, errImageScriptedWrite.Error(), "first failed write")
}

func testImageRoundOutcomeClose(t *testing.T) {
	f, round := newImageRound(t, 3, 0, 1)
	ready, writing := newImageHookCtx(), newImageHookCtx()
	f.admitted(t, round, ready, 0, 1, 1)
	ready.endAndRun(errImageRequestEnd)
	stall, inWrite := f.stalledRequest(t, round, writing, 0, 2)
	defer close(stall.release)
	writing.endAndRun(errImageRequestEnd)
	synctest.Wait()
	f.admitted(t, round, t.Context(), 1, 3, 1)
	other := f.round(t, imageTestLimits(), 2)
	sibling := newImageHookCtx()
	f.admitted(t, other, sibling, 2, 4, 1)
	waiting, independent := goTakeImage(round, t.Context(), 3), goTakeImage(other, t.Context(), 4)
	synctest.Wait()
	requireImageWaiting(t, waiting, "round waiter")
	requireImageWaiting(t, independent, "independent waiter")
	reads := f.clock.readCount()
	copied := *round
	copied.Close()
	requireImageResult(t, f.request(other, t.Context(), 2, 3), 2, 3, nil, "independent round reuses the already-written start")
	requireQueryResult(t, awaitImageResult(t, waiting, "closed round waiter"), consensus.UTXOImageQuery{}, errImageRoundClosed, "closed round waiter")
	synctest.Wait()
	requireEqual(t, f.clock.readCount(), reads+3, "clock reads by round close and replacement request")
	requireImageWaiting(t, independent, "independent round after close")
	assertImageRoundClosed(t, f, round)
	stall.release <- nil
	requireImageResult(t, awaitImageResult(t, inWrite, "write after round close"), 2, 2, nil, "write after round close")
	requireImageAbsent(t, round, t.Context(), 2, errImageRoundClosed)
	sibling.endAndRun(errImageRoundEnd)
	requireImageResult(t, awaitImageResult(t, independent, "independent waiter"), 1, 4, errImageRoundEnd, "independent waiter")
	requireEqual(t, len(round.outcomes), 0, "queued records after close")
}

func assertImageRoundClosed(t *testing.T, f *imageTestFixture, round *ImageRound) {
	t.Helper()
	for _, start := range []byte{1, 2, 3, 5} {
		requireImageAbsent(t, round, t.Context(), start, errImageRoundClosed)
	}
	f.refused(t, round, t.Context(), 1, 3, errImageRoundClosed)
	reads := f.clock.readCount()
	round.Close()
	requireEqual(t, f.clock.readCount(), reads, "clock reads by repeated round close")
}

func testImageServiceOutcomeClose(t *testing.T) {
	inImageBubble(func(t *testing.T) {
		f, round := newImageRound(t, 4, 0, 1, 2, 3)
		ready, waiting := newImageHookCtx(), newImageHookCtx()
		f.admitted(t, round, ready, 0, 1, 1)
		ready.endAndRun(errImageRequestEnd)
		synctest.Wait()
		inst := f.admitted(t, round, waiting, 1, 2, 1)
		wait := goTakeImage(round, t.Context(), 2)
		synctest.Wait()
		requireImageWaiting(t, wait, "passive waiter")
		requireEqual(t, f.leases(), uint64(0), "leases at the passive wait")
		entered, release := f.holdImageFrame(t, 2, func() {})
		defer release()
		send := f.goRequest(round, t.Context(), 2, 3)
		requireChannelClosed(t, entered, "actual writer")
		checkImageServiceOutcomeClose(t, f, round, wait, send, release)
		assertImageRequesterDetached(t, f, round)
		reads := f.clock.readCount()
		waiting.endAndRun(errImageRoundEnd)
		synctest.Wait()
		requireEqual(t, f.clock.readCount(), reads, "clock reads by a callback after Close")
		requireEqual(t, inst.ref.Load(), (*imageInstance)(nil), "callback reference after Close")
		requireEqual(t, f.owners(round, 2), imageOwners{
			peerKeys: 3, peerKey: true, attempted: 3, starts: 3,
			perPeer: imageUsage(0, 1, 1, 1, 0), global: imageUsage(0, 3, 3, 3, 0),
		}, "round work retained and requester registry empty at Close")
	})(t)
}

func assertImageRequesterDetached(t *testing.T, f *imageTestFixture, round *ImageRound) {
	t.Helper()
	req := f.lockRequester()
	current, sessions := len(req.current), len(req.sessions)
	detached := [4]bool{
		round.sources[f.ids[0]].transport == nil,
		round.sources[f.ids[1]].transport == nil,
		round.sources[f.ids[2]].transport == nil,
		round.sources[f.ids[3]].transport == nil,
	}
	req.mu.Unlock()
	requireEqual(t, current, 0, "joined requester current registry")
	requireEqual(t, sessions, 0, "joined requester session registry")
	requireEqual(t, detached, [4]bool{true, true, true, true}, "captured transports after Close")
}

func checkImageServiceOutcomeClose(t *testing.T, f *imageTestFixture, round *ImageRound, wait, send <-chan imageResult, release func()) {
	t.Helper()
	first := lifecycleClose(f.s)
	for _, conn := range f.conns {
		requireChannelClosed(t, conn.closed, "connection close during drain")
	}
	second := lifecycleClose(f.s)
	synctest.Wait()
	requireQueryResult(t, awaitImageResult(t, wait, "waiter on drain"), consensus.UTXOImageQuery{}, errServiceClosed, "waiter on drain")
	requireStillBlocked(t, first, "first Close while actual write is held")
	requireStillBlocked(t, second, "second Close while actual write is held")
	requireImageAbsent(t, round, nil, 1, errServiceClosed)
	f.refused(t, round, nil, 2, 4, errServiceClosed)
	f.requireRoundRefused(t, nil, f.config(imageTestLimits(), 2), errServiceClosed, "constructor while draining")
	round.Close()
	require(t, !round.closed && len(round.outcomes[imageStart(1)]) == 1, "late round close changed the ready result")
	release()
	requireImageResult(t, awaitImageResult(t, send, "drained writer"), 1, 3, net.ErrClosed, "drained writer")
	requireReturned(t, first, "first Close")
	requireReturned(t, second, "second Close")
	requireImageAbsent(t, round, t.Context(), 1, errServiceClosed)
}

func testImageLeasedReceive(t *testing.T) {
	f, round := newImageRound(t, 1, 0)
	ctx := newImageHookCtx()
	f.admitted(t, round, ctx, 0, 1, 1)
	ctx.end(errImageRequestEnd)
	requireImageAbsent(t, round, t.Context(), 2, errImageNoAssignment)
	req := f.lockRequester()
	unlock := sync.OnceFunc(req.mu.Unlock)
	defer unlock()
	leased := goTakeImage(round, t.Context(), 1)
	waitUntil(t, func() bool { return f.leases() == 1 }, "Receive work lease")
	requireParked(t, "leased Receive at the requester mutex", "[sync.Mutex.Lock", "p2p.(*ImageRound).receiveOnce(")
	closed := lifecycleClose(f.s)
	waitDraining(t, f.s)
	requireImageAbsent(t, round, t.Context(), 1, errServiceClosed)
	requireStillBlocked(t, closed, "Close while leased Receive holds its decision")
	unlock()
	requireImageResult(t, awaitImageResult(t, leased, "leased Receive result"), 1, 1, errImageRequestEnd, "leased Receive result")
	requireReturned(t, closed, "Close after leased Receive")
	requireImageAbsent(t, round, t.Context(), 1, errServiceClosed)
}

type imageWaitBarrier struct {
	context.Context
	entered chan struct{}
	release <-chan struct{}
}

func (c imageWaitBarrier) Done() <-chan struct{} {
	close(c.entered)
	<-c.release
	return c.Context.Done()
}

func testImagePassiveReceiveJoin(t *testing.T) {
	f, round := newImageRound(t, 1, 0)
	f.admitted(t, round, t.Context(), 0, 1, 1)
	entered, gate := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	wait := goTakeImage(round, imageWaitBarrier{Context: t.Context(), entered: entered, release: gate}, 1)
	requireChannelClosed(t, entered, "Receive entering its passive wait")
	requireReturned(t, lifecycleClose(f.s), "Close while the passive wait has not returned")
	release()
	requireQueryResult(t, awaitImageResult(t, wait, "passive wait after join"), consensus.UTXOImageQuery{}, errServiceClosed, "passive wait after join")
}

func testImageTerminalHooks(t *testing.T) {
	for _, terminal := range []string{"peer exit", "round close", "service close", "receive pass"} {
		t.Run(terminal, inImageBubble(func(t *testing.T) { checkImageTerminalHooks(t, terminal) }))
	}
	t.Run("Done notification after service close", inImageBubble(testImageDoneNotificationAfterClose))
	t.Run("Done notifications stop on close", testImageDoneSignalsStopOnClose)
	t.Run("Done closes during registration", testImageDoneDuringRegistration)
	t.Run("custom AfterFunc scheduling cause", testImageAfterFuncHandoffCause)
}

func testImageTerminalObservationUnwind(t *testing.T) {
	t.Run("round close clock Goexit", inImageBubble(testImageRoundCloseObservationUnwind))
	t.Run("peer exit context panic", inImageBubble(testImagePeerExitObservationUnwind))
}

func requireImageTerminalUnwind(t *testing.T, run func(), goexit bool) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		report := any(imageGoexit)
		defer func() { done <- cmp.Or(recover(), report) }()
		run()
		report = nil
	}()
	requireImageUnwindValue(t, awaitImageResult(t, done, "terminal observation unwind"), goexit)
}

func testImageRoundCloseObservationUnwind(t *testing.T) {
	f, round := newImageRound(t, 2, 0)
	other := f.round(t, imageTestLimits(), 1)
	f.admitted(t, round, t.Context(), 0, 1, 1)
	release := f.holdWrite(t, 0)
	defer func() { must(t, release(), "holder write") }()
	queued := f.goRequest(round, t.Context(), 0, 2)
	f.waitAdmitted(t, 0, 2, "queued request")
	waiting := goTakeImage(round, t.Context(), 1)
	synctest.Wait()
	requireImageWaiting(t, queued, "request waiting for writeMu")
	requireImageWaiting(t, waiting, "assigned start waiter")
	f.clock.onReadFrom(".(*ImageRound).Close", func(now time.Time) time.Time {
		imageUnwinder(true)()
		return now
	})
	requireImageTerminalUnwind(t, round.Close, true)

	got := f.request(other, t.Context(), 1, 1)
	require(t, got.err == nil && got.q == expectedImageQuery(1, 1), "Request after closing round clock unwind: query %+v, error %v", got.q, got.err)
	requireImageResult(t, f.request(other, t.Context(), 1, 2), 2, 2, nil, "queued start available after round close")
	requireImageResult(t, awaitImageResult(t, queued, "queued request after round close"), 2, 2, errImageRoundClosed, "queued request after round close")
	requireQueryResult(t, awaitImageResult(t, waiting, "waiter after round close"), consensus.UTXOImageQuery{}, errImageRoundClosed, "waiter after round close")
	f.requireFrames(t, 0, "frames after round close", expectedImageQuery(1, 1))
}

type imageTerminalPanicCtx struct {
	*imageHookCtx
	observe <-chan bool
	first   chan<- int
	index   int
}

func (c *imageTerminalPanicCtx) Err() error {
	select {
	case due := <-c.observe:
		if due {
			c.end(errImageRequestEnd)
			c.first <- c.index
		} else {
			imageUnwinder(false)()
		}
	default:
	}
	return c.imageHookCtx.Err()
}

func testImagePeerExitObservationUnwind(t *testing.T) {
	f, round := newImageRound(t, 2, 0, 1)
	observe, first := make(chan bool, 2), make(chan int, 1)
	starts := [2]byte{1, 2}
	var waiting [2]<-chan imageResult
	for i, start := range starts {
		ctx := &imageTerminalPanicCtx{imageHookCtx: newImageHookCtx(), observe: observe, first: first, index: i}
		f.admitted(t, round, ctx, 0, start, uint64(i+1))
		waiting[i] = goTakeImage(round, t.Context(), start)
	}
	f.admitted(t, round, t.Context(), 1, 3, 1)
	synctest.Wait()
	for _, waiter := range waiting {
		requireImageWaiting(t, waiter, "exiting source assignment waiter")
	}
	requireImageTerminalUnwind(t, func() {
		observe <- true
		observe <- false
		f.s.unregisterPeer(f.peers[0])
	}, false)
	due := awaitImageResult(t, first, "first terminal context")
	interrupted := 1 - due
	start := starts[interrupted]

	got := f.request(round, t.Context(), 1, start)
	require(t, got.err == nil && got.q == expectedImageQuery(2, start), "Request after exiting peer context unwind: query %+v, error %v", got.q, got.err)
	requireImageResult(t, awaitImageResult(t, waiting[due], "observed context outcome"), uint64(due+1), starts[due], errImageRequestEnd, "observed context outcome")
	requireImageResult(t, awaitImageResult(t, waiting[interrupted], "interrupted context outcome"), uint64(interrupted+1), start, errImageDisconnected, "interrupted context outcome")
	requireQueryResult(t, f.request(round, t.Context(), 0, start), consensus.UTXOImageQuery{}, errImageDisconnected, "request on retired source")
	wait, cancel := context.WithCancel(t.Context())
	cancel()
	requireImageAbsent(t, round, wait, starts[due], errImageNoAssignment)
	requireImageAbsent(t, round, wait, start, context.Canceled)
	requireImageAbsent(t, round, wait, 3, context.Canceled)
	f.requireFrames(t, 0, "frames before peer exit", expectedImageQuery(1, 1), expectedImageQuery(2, 2))
}

func checkImageTerminalHooks(t *testing.T, terminal string) {
	f := newImageTestFixture(t, 2)
	ctx, owner := newImageHookCtx(), newImageHookCtx()
	round := f.roundCtx(t, owner, imageTestLimits(), 0)
	called, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	mark := sync.OnceFunc(func() { close(called) })
	stop := func() { mark(); <-release }
	ctx.onStop, owner.onStop = stop, stop
	inst := f.admitted(t, round, ctx, 0, 1, 1)
	ctx.end(errImageRequestEnd)
	owner.end(errImageRoundEnd)
	reads := f.clock.readCount()
	errReads := imageContextReads(ctx, owner)
	if terminal == "receive pass" {
		requireImageTake(t, round, t.Context(), 1, expectedImageQuery(1, 1), errImageRequestEnd, "end pass ready result")
	} else {
		complete := make(chan struct{})
		go func() { applyImageTerminal(f, round, terminal); close(complete) }()
		requireChannelClosed(t, complete, "terminal adapter completion")
		requireImageTerminalOutcome(t, round, terminal)
	}
	require(t, !isClosed(called), "terminal adapter invoked a caller-controlled stop")
	if terminal == "service close" {
		requireEqual(t, f.clock.readCount(), reads, "clock reads by final requester teardown")
		requireEqual(t, imageContextReads(ctx, owner), errReads, "context reads by final requester teardown")
	}
	checkImageInertHooks(t, f, round, terminal, ctx, owner)
	requireEqual(t, inst.ref.Load(), (*imageInstance)(nil), "retired callback instance")
	requireEqual(t, inst.timer.Stop(), false, "directly owned timer stopped at retirement")
}

func imageContextReads(ctx, owner *imageHookCtx) [2][3]int64 {
	return [2][3]int64{ctx.readCounts(), owner.readCounts()}
}

func checkImageInertHooks(t *testing.T, f *imageTestFixture, round *ImageRound, terminal string, ctx, owner *imageHookCtx) {
	t.Helper()
	session, want, callReads := 0, errServiceClosed, 0
	if terminal != "service close" {
		round = f.round(t, imageTestLimits(), 1)
		f.admitted(t, round, t.Context(), 1, 1, 1)
		session, want, callReads = 1, errImageAssignmentCurrent, 1
	}
	before := f.clock.readCount()
	contextReads := imageContextReads(ctx, owner)
	callbacks := [2]int{ctx.endAndRun(context.Canceled), owner.endAndRun(context.Canceled)}
	synctest.Wait()
	requireQueryResult(t, f.request(round, t.Context(), session, 1), consensus.UTXOImageQuery{}, want, "Request after delayed callbacks")
	requireEqual(t, callbacks, [2]int{1, 1}, "retained external callbacks")
	requireEqual(t, imageContextReads(ctx, owner), contextReads, "caller context Done, Err and Value reads with inert callbacks")
	requireEqual(t, f.clock.readCount(), before+callReads, "clock reads with inert callbacks")
}

func testImageDoneNotificationAfterClose(t *testing.T) {
	f, round := newImageRound(t, 1, 0)
	ctx := newImageHookCtx()
	caller := struct{ context.Context }{Context: ctx}
	inst := f.admitted(t, round, caller, 0, 1, 1)
	synctest.Wait()
	requireReturned(t, lifecycleClose(f.s), "Close before the Done notification")
	contextReads, clockReads := ctx.readCounts(), f.clock.readCount()
	ctx.end(errImageRequestEnd)
	synctest.Wait()
	requireQueryResult(t, f.request(round, caller, 0, 1), consensus.UTXOImageQuery{}, errServiceClosed, "Request after the Done notification")
	requireEqual(t, ctx.readCounts(), contextReads, "caller context Done, Err and Value reads after the Done notification")
	requireEqual(t, f.clock.readCount(), clockReads, "clock reads after the Done notification")
	requireEqual(t, inst.ref.Load(), (*imageInstance)(nil), "callback reference after the Done notification")
}

func testImageDoneSignalsStopOnClose(t *testing.T) {
	for _, terminal := range []string{"round close", "service close"} {
		t.Run(terminal, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			ctx := newImageHookCtx()
			defer ctx.end(context.Canceled)
			caller := struct{ context.Context }{Context: ctx}
			round := f.roundCtx(t, caller, imageTestLimits(), 0)
			inst := f.admitted(t, round, caller, 0, 1, 1)
			synctest.Wait()

			if terminal == "round close" {
				round.Close()
			} else {
				requireReturned(t, lifecycleClose(f.s), "Close with open Done notifications")
			}
			requireImageTerminalOutcome(t, round, terminal)
			requireEqual(t, inst.stopCtx(), false, "request Done notification still stoppable after close")
			requireEqual(t, inst.stopRound(), false, "round Done notification still stoppable after close")
		}))
	}
}

func testImageDoneDuringRegistration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		goexit bool
	}{{"panic", false}, {"Goexit", true}} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f, round := newImageRound(t, 1, 0)
			parent := newImageHookCtx()
			unwind := imageUnwinder(tc.goexit)
			caller := &imageUnwindHookCtx{
				imageHookCtx: parent,
				onDone:       func() { parent.end(errImageRequestEnd) },
				onErr: func() {
					if imageCalledFrom("context.(*cancelCtx).propagateCancel") {
						unwind()
					}
				},
			}
			report := awaitImageResult(t, f.goRecovered(round, caller, 0, 1), "request interrupted during cancellation registration")
			got := f.request(round, t.Context(), 0, 2)
			requireImageResult(t, got, 1, 2, nil, "request ID after synchronous context observation")
			requireImageUnwindValue(t, report, tc.goexit)
		}))
	}
}

type imageRetentionKey struct{}

type imageRetentionValueCtx struct {
	context.Context
	service *Service
}

func (c imageRetentionValueCtx) Value(any) any { return c.service }

type imageRetentionAfterFuncCtx struct {
	context.Context
	parent     *imageHookCtx
	onRegister func(func())
}

func (c imageRetentionAfterFuncCtx) AfterFunc(f func()) func() bool {
	stop := c.parent.AfterFunc(f)
	c.onRegister(f)
	return func() bool {
		stopped := stop()
		runtime.KeepAlive(c.Context)
		return stopped
	}
}

type imageAfterFuncCauseCtx struct {
	*imageHookCtx
	parent context.Context
}

func (c imageAfterFuncCauseCtx) Value(key any) any { return c.parent.Value(key) }

type imageServiceCancelError struct{ service *Service }

func (e imageServiceCancelError) Error() string {
	runtime.KeepAlive(e.service)
	return "caller cancellation cause"
}

func testImageAfterFuncHandoffCause(t *testing.T) {
	f := newImageTestFixture(t, 0)
	parent, cancel := context.WithCancelCause(context.Background())
	cancel(imageServiceCancelError{service: f.s})
	caller := imageAfterFuncCauseCtx{imageHookCtx: newImageHookCtx(), parent: parent}
	adapted, _ := imageCancellationContext(caller)
	var cause error
	caller.onAfterFunc = func() {
		caller.end(context.Canceled)
		cause = context.Cause(adapted)
	}
	stop := context.AfterFunc(adapted, func() {})
	defer stop()
	requireEqual(t, cause, context.Canceled, "cause during caller AfterFunc registration")
}

func testImageTerminalServiceRetention(t *testing.T) {
	t.Run("native parent", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		defer cancel()
		checkImageTerminalServiceRetention(t, func(s *Service) context.Context {
			return context.WithValue(parent, imageRetentionKey{}, s)
		})
		runtime.KeepAlive(parent)
	})
	t.Run("Done fallback", func(t *testing.T) {
		parent := newImageHookCtx()
		defer parent.end(context.Canceled)
		checkImageTerminalServiceRetention(t, func(s *Service) context.Context {
			return imageRetentionValueCtx{Context: parent, service: s}
		})
		runtime.KeepAlive(parent)
	})
	t.Run("custom AfterFunc", func(t *testing.T) {
		parent := newImageHookCtx()
		var service weak.Pointer[Service]
		if t.Run("publish and join", inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			round := requestImageWithEarlyCancellation(t, f, parent)
			service = closeImageServiceForRetention(t, f, round)
		})) {
			requireImageServiceReleased(t, service)
			requireEqual(t, parent.endAndRun(context.Canceled), 1, "inert callback retained by caller context")
		}
	})
}

func requestImageWithEarlyCancellation(t *testing.T, f *imageTestFixture, parent *imageHookCtx) *ImageRound {
	t.Helper()
	var done <-chan struct{}
	var parked bool
	owner := newImageHookCtx()
	owner.onAfterFunc = func() {
		if parked {
			<-done
		}
	}
	parentCtx, cancel := context.WithCancelCause(context.Background())
	cancel(imageServiceCancelError{service: f.s})
	caller := imageRetentionAfterFuncCtx{
		Context: imageAfterFuncCauseCtx{imageHookCtx: parent, parent: parentCtx},
		parent:  parent,
		onRegister: func(notify func()) {
			parent.end(context.Canceled)
			done, parked = runImageCallbackDuringRegistration(notify)
		},
	}
	round := f.roundCtx(t, owner, imageTestLimits(), 0)
	got := f.request(round, caller, 0, 1)
	requireImageResult(t, got, 1, 1, context.Canceled, "Request canceled during callback registration")
	require(t, parked, "caller callback did not reach cancellation during registration")
	return round
}

func runImageCallbackDuringRegistration(notify func()) (<-chan struct{}, bool) {
	done := make(chan struct{})
	started := make(chan string, 1)
	go func() {
		defer close(done)
		var stack [256]byte
		id := bytes.Fields(stack[:runtime.Stack(stack[:], false)])[1]
		started <- "goroutine " + string(id) + " [sync.Mutex.Lock"
		notify()
	}()
	prefix := []byte(<-started)
	stacks := make([]byte, 1<<20)
	for range 1 << 16 {
		n := runtime.Stack(stacks, true)
		if n == len(stacks) {
			return done, false
		}
		_, tail, found := bytes.Cut(stacks[:n], prefix)
		if found {
			stack, _, _ := bytes.Cut(tail, []byte("\n\n"))
			if bytes.Contains(stack, []byte("context.(*cancelCtx).cancel(")) {
				return done, true
			}
		}
		runtime.Gosched()
	}
	return done, false
}

func checkImageTerminalServiceRetention(t *testing.T, caller func(*Service) context.Context) {
	t.Helper()
	var service weak.Pointer[Service]
	if !t.Run("publish and join", func(t *testing.T) {
		f, round := newImageRound(t, 1, 0)
		f.admitted(t, round, caller(f.s), 0, 1, 1)
		service = closeImageServiceForRetention(t, f, round)
	}) {
		t.FailNow()
	}
	requireImageServiceReleased(t, service)
}

func closeImageServiceForRetention(t *testing.T, f *imageTestFixture, round *ImageRound) weak.Pointer[Service] {
	t.Helper()
	requireReturned(t, lifecycleClose(f.s), "Close with registered context callback")
	requireImageAbsent(t, round, t.Context(), 1, errServiceClosed)
	return weak.Make(f.s)
}

func requireImageServiceReleased(t *testing.T, service weak.Pointer[Service]) {
	t.Helper()
	runtime.GC()
	require(t, service.Value() == nil, "retained context callback keeps the closed Service alive")
}

func applyImageTerminal(f *imageTestFixture, round *ImageRound, terminal string) {
	switch terminal {
	case "peer exit":
		f.s.unregisterPeer(f.peers[0])
	case "round close":
		round.Close()
	case "service close":
		_ = f.s.Close()
	}
}

func requireImageTerminalOutcome(t *testing.T, round *ImageRound, terminal string) {
	t.Helper()
	switch terminal {
	case "peer exit":
		requireImageTake(t, round, t.Context(), 1, expectedImageQuery(1, 1), errImageRequestEnd, "due error at peer exit")
	case "round close":
		requireImageAbsent(t, round, t.Context(), 1, errImageRoundClosed)
	case "service close":
		requireImageAbsent(t, round, t.Context(), 1, errServiceClosed)
	}
}

const (
	imageWorkerHost = "198.51.100.40"
	imageWorkerAddr = imageWorkerHost + ":19110"
)

type imageExitingWorker struct {
	round *ImageRound
	fail  func()
	done  <-chan struct{}
	wire  *imageWire
}

func startImageExitingWorker(t *testing.T, f *imageTestFixture, command string) imageExitingWorker {
	t.Helper()
	f.s.reconnectMu.Lock()
	resume := sync.OnceFunc(f.s.reconnectMu.Unlock)
	defer resume()
	local, remote := net.Pipe()
	conn := newBlockRetryConn(endpointConn{Conn: local, remote: stubAddr(imageWorkerAddr)})
	t.Cleanup(func() { _ = remote.Close() })
	announcing, fail := make(chan struct{}), make(chan struct{})
	failWrite := sync.OnceFunc(func() { close(fail) })
	t.Cleanup(failWrite)
	wire := &imageWire{closed: conn.closed}
	conn.writeHook = imageExitingWorkerWrites(local, wire, command, announcing, fail)
	done := startImagePipeWorker(t, f.s, conn, remote)
	waitUntil(t, func() bool { return f.serviceEntry(imageWorkerAddr) != nil }, "peer registration")
	config := ImageRoundConfig{Anchor: imageTestAnchor, Limits: imageTestLimits(), SourceIDs: []string{imageWorkerAddr}}
	round, err := f.begin(t.Context(), config)
	must(t, err, "capture the actual peer")
	got := requestWithin(lifecycleWatchdog, round, t.Context(), imageWorkerAddr, 1, imageTestByteLimit)
	requireImageResult(t, got, 1, 1, nil, "request before the first announcement")
	resume()
	if command == "getblocks" {
		cfg := f.s.cfg.PeerRuntimeConfig
		frame, err := readFrame(remote, networkMagic(cfg.Network), cfg.MaxMessageSize)
		must(t, err, "read the first announcement")
		requireEqual(t, frame.Command, "sendcmpct", "announcement before the block request")
	}
	requireChannelClosed(t, announcing, "target announcement write")
	return imageExitingWorker{round: round, fail: failWrite, done: done, wire: wire}
}

func startImagePipeWorker(t *testing.T, s *Service, local, remote net.Conn) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	require(t, s.acquireWork(), "worker lease refused")
	go func() { defer close(done); s.runConn(local, false) }()
	cfg := s.cfg.PeerRuntimeConfig
	must(t, remote.SetDeadline(time.Now().Add(lifecycleWatchdog)), "remote deadline")
	must(t, completeRemoteHandshake(remote, cfg, testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0)), "remote handshake")
	return done
}

func imageExitingWorkerWrites(conn net.Conn, wire *imageWire, terminalCommand string, announcing chan<- struct{}, fail <-chan struct{}) func([]byte) (int, error) {
	imagePayload := false
	return func(b []byte) (int, error) {
		if imagePayload {
			imagePayload = false
			return wire.write(b)
		}
		if len(b) == wireHeaderSize {
			command := b[4:16]
			if string(bytes.TrimRight(command, "\x00")) == terminalCommand {
				close(announcing)
				<-fail
				return 0, errImageScriptedWrite
			}
			if [12]byte(command) == imageRequestCommand {
				imagePayload = true
				return wire.write(b)
			}
		}
		return conn.Write(b)
	}
}

func testImageExitAtQuota(t *testing.T) {
	f := newImageTestFixture(t, 0)
	worker := startImageExitingWorker(t, f, "sendcmpct")
	old := f.serviceEntry(imageWorkerAddr)
	config := ImageRoundConfig{Anchor: imageTestAnchor, Limits: imageTestLimits(), SourceIDs: []string{imageWorkerAddr}}
	release := sync.OnceFunc(f.s.lockPeerQuotaKey(imageWorkerHost))
	defer release()
	worker.fail()
	requireParked(t, "actual worker at exit quota lock", peerExitFrames...)
	checkImageExitAtQuota(t, f, worker.round, config, old)
	release()
	requireChannelClosed(t, worker.done, "connection worker exit")
	requireEqual(t, len(worker.wire.bytes()), wireHeaderSize+120, "admitted wire length")
}

func checkImageExitAtQuota(t *testing.T, f *imageTestFixture, round *ImageRound, config ImageRoundConfig, old *peer) {
	t.Helper()
	got := requestWithin(lifecycleWatchdog, round, t.Context(), imageWorkerAddr, 2, imageTestByteLimit)
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageDisconnected, "request before peer registry cleanup")
	f.requireRoundRefused(t, t.Context(), config, errImageSourceSet, "constructor before peer registry cleanup")
	requireImageTake(t, round, t.Context(), 1, expectedImageQuery(1, 1), errImageDisconnected, "result before peer registry cleanup")
	requireImageAbsent(t, round, t.Context(), 1, errImageNoAssignment)
	requireEqual(t, f.serviceEntry(imageWorkerAddr), old, "registry entry while quota cleanup waits")
	requireEqual(t, old.snapshotState().LastError, errImageScriptedWrite.Error(), "first announcement failure")
}

func testImageExitBeforeRetryJoin(t *testing.T) {
	f := newImageTestFixture(t, 0)
	s := blockRetryService(t, f.s)
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	parked, gate := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	conn := newBlockRetryConn(endpointConn{Conn: local, remote: stubAddr(imageWorkerAddr)})
	conn.writeHook = func(b []byte) (int, error) {
		if len(b) != wireHeaderSize || !bytes.Equal(bytes.TrimRight(b[4:16], "\x00"), []byte("getdata")) {
			return local.Write(b)
		}
		close(parked)
		<-gate
		return 0, net.ErrClosed
	}
	worker := startImagePipeWorker(t, s, conn, remote)
	round := admitImageToPlainPeer(t, f, remote)
	current := f.serviceEntry(imageWorkerAddr)
	require(t, current != nil, "plain peer missing from the registry")
	notify := make(chan struct{})
	slot := armBlockRetrySlot(t, current, [32]byte{0xab}, notify, time.Now())
	close(notify)
	requireChannelClosed(t, parked, "retry writer entered getdata")
	must(t, remote.Close(), "end the peer read loop")
	requireChannelClosed(t, conn.closed, "retry cleanup closes the connection")
	requireParked(t, "worker waits for the retry writer", "[chan receive]", "p2p.(*peer).finishBlockRetry(", "p2p.(*Service).handleConn(")
	wait, cancel := context.WithCancel(t.Context())
	cancel()
	requireImageTake(t, round, wait, 1, expectedImageQuery(1, 1), errImageDisconnected, "result before retry join")
	got := requestWithin(lifecycleWatchdog, round, t.Context(), imageWorkerAddr, 2, imageTestByteLimit)
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageDisconnected, "request before retry join")
	requireImageAbsent(t, round, t.Context(), 1, errImageNoAssignment)
	requireEqual(t, f.serviceEntry(imageWorkerAddr), current, "peer registry before retry join")
	release()
	requireChannelClosed(t, worker, "peer worker joins the retry")
	requireChannelClosed(t, slot.done, "retry lease released")
}

func testImageAnnouncementExitBeforePublish(t *testing.T) {
	for _, command := range []string{"sendcmpct", "getblocks"} {
		t.Run(command, func(t *testing.T) {
			f := newImageTestFixture(t, 0)
			worker := startImageExitingWorker(t, f, command)
			current := f.serviceEntry(imageWorkerAddr)
			checkImageExitBeforePublish(t, f.s, worker.round, worker.fail)
			requireChannelClosed(t, worker.done, "connection worker exit")
			requireEqual(t, current.snapshotState().LastError, errImageScriptedWrite.Error(), "announcement failure diagnostic")
		})
	}
}

type imageReadFailureConn struct{ net.Conn }

func (c imageReadFailureConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func testImageReadExitBeforePublish(t *testing.T) {
	f := newImageTestFixture(t, 0)
	worker := startImageReadFailureWorker(t, f)
	current := f.serviceEntry(imageWorkerAddr)
	checkImageExitBeforePublish(t, f.s, worker.round, worker.fail)
	requireChannelClosed(t, worker.done, "connection worker exit")
	requireEqual(t, current.snapshotState().LastError, io.ErrUnexpectedEOF.Error(), "read failure diagnostic")
}

func startImageReadFailureWorker(t *testing.T, f *imageTestFixture) imageExitingWorker {
	t.Helper()
	s := blockRetryService(t, f.s)
	s.cfg.PeerRuntimeConfig.ReadDeadline = 0
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	conn := imageReadFailureConn{endpointConn{Conn: local, remote: stubAddr(imageWorkerAddr)}}
	done := startImagePipeWorker(t, s, conn, remote)
	round := admitImageToPlainPeer(t, f, remote)
	requireParked(t, "worker waiting for a frame", "[select", "net.(*pipe).read(", "p2p.(*peer).run(")
	fail := func() { must(t, remote.Close(), "end the frame read") }
	return imageExitingWorker{round: round, fail: fail, done: done}
}

func testImageTransportExitUnwind(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		f := newImageTestFixture(t, 0)
		checkImageTransportExitUnwind(t, f, startImageReadFailureWorker(t, f), io.ErrUnexpectedEOF)
	})
	for _, command := range []string{"sendcmpct", "getblocks"} {
		t.Run(command, func(t *testing.T) {
			f := newImageTestFixture(t, 0)
			checkImageTransportExitUnwind(t, f, startImageExitingWorker(t, f, command), errImageScriptedWrite)
		})
	}
}

func checkImageTransportExitUnwind(t *testing.T, f *imageTestFixture, worker imageExitingWorker, want error) {
	t.Helper()
	release := holdPeerExit(t, f.s, imageWorkerAddr)
	defer release()
	sampled := make(chan struct{})
	f.clock.onReadFrom(".(*imageRequester).retireImageOwnerLocked", func(now time.Time) time.Time {
		close(sampled)
		imageUnwinder(true)()
		return now
	})
	worker.fail()
	requireChannelClosed(t, sampled, "terminal requester clock read")
	requireParked(t, "worker at exit quota lock after clock unwind", peerExitFrames...)
	states := f.s.cfg.PeerManager.Snapshot()
	requireEqual(t, len(states), 1, "registered peer count at exit")
	requireEqual(t, states[0].Addr, imageWorkerAddr, "registered peer at exit")
	requireEqual(t, states[0].LastError, want.Error(), "transport diagnostic after retirement unwind")
	requireImageTake(t, worker.round, t.Context(), 1, expectedImageQuery(1, 1), errImageDisconnected, "outcome after retirement unwind")
	got := requestWithin(lifecycleWatchdog, worker.round, t.Context(), imageWorkerAddr, 2, imageTestByteLimit)
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageDisconnected, "request after retirement unwind")
	requireImageAbsent(t, worker.round, t.Context(), 1, errImageNoAssignment)
	release()
	requireChannelClosed(t, worker.done, "connection worker exit")
}

func checkImageExitBeforePublish(t *testing.T, s *Service, round *ImageRound, trigger func()) {
	t.Helper()
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	trigger()
	requireParked(t, "worker waiting to publish peer diagnostics", "[sync.RWMutex.RLock", "p2p.(*Service).publishPeerStateIfOwner(", "p2p.(*Service).handleConn(")
	wait, cancel := context.WithCancel(t.Context())
	cancel()
	requireImageTake(t, round, wait, 1, expectedImageQuery(1, 1), errImageDisconnected, "result before peer diagnostics")
	got := requestWithin(lifecycleWatchdog, round, t.Context(), imageWorkerAddr, 2, imageTestByteLimit)
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageDisconnected, "request before peer diagnostics")
	requireImageAbsent(t, round, t.Context(), 1, errImageNoAssignment)
}

func admitImageToPlainPeer(t *testing.T, f *imageTestFixture, remote net.Conn) *ImageRound {
	t.Helper()
	cfg := f.s.cfg.PeerRuntimeConfig
	read := func() message {
		frame, err := readFrame(remote, networkMagic(cfg.Network), cfg.MaxMessageSize)
		must(t, err, "read the peer frame")
		return frame
	}
	for read().Command != messageGetAddr {
	}
	config := ImageRoundConfig{Anchor: imageTestAnchor, Limits: imageTestLimits(), SourceIDs: []string{imageWorkerAddr}}
	round, err := f.begin(t.Context(), config)
	must(t, err, "capture the plain peer")
	sent := launch(round, t.Context(), imageWorkerAddr, 1, imageTestByteLimit)
	frame := read()
	require(t, isImageRequestCommand(frame.Command), "plain peer received %q", frame.Command)
	query, ok := consensus.DecodeUTXOImageRequest(frame.Payload)
	require(t, ok, "plain peer received an invalid query")
	requireEqual(t, query, expectedImageQuery(1, 1), "query sent to the plain peer")
	requireImageResult(t, awaitImageResult(t, sent, "write to the plain peer"), 1, 1, nil, "write to the plain peer")
	wait, cancel := context.WithCancel(t.Context())
	cancel()
	requireImageAbsent(t, round, wait, 1, context.Canceled)
	return round
}

func testImageExitWithLiveReplacement(t *testing.T) {
	f, original := newImageRound(t, 1, 0)
	f.admitted(t, original, t.Context(), 0, 1, 1)
	newer := f.addSession(t, f.ids[0], "192.0.2.81:9")
	replacement := f.round(t, imageTestLimits(), newer)
	f.admitted(t, replacement, t.Context(), newer, 2, 1)
	wait, cancel := context.WithCancel(t.Context())
	cancel()

	f.s.unregisterPeer(f.peers[0])
	requireImageTake(t, replacement, wait, 2, consensus.UTXOImageQuery{}, context.Canceled, "replacement still current after original exit")
	requireImageTake(t, original, t.Context(), 1, expectedImageQuery(1, 1), errImageDisconnected, "original registration's disconnect")
	requireImageAbsent(t, original, t.Context(), 1, errImageNoAssignment)
	f.s.unregisterPeer(f.peers[0])
	requireImageResult(t, f.request(replacement, t.Context(), newer, 3), 2, 3, nil, "replacement request after repeated original exit")
}

func testImageReplacementRetainsNoPeer(t *testing.T) {
	f, used := newImageRound(t, 1, 0)
	unused := f.round(t, imageTestLimits(), 0)
	alias, err := f.begin(t.Context(), ImageRoundConfig{Anchor: imageTestAnchor, Limits: imageTestLimits(), SourceIDs: []string{"192.0.2.40:9"}})
	must(t, err, "capture the old alias")
	f.admitted(t, used, t.Context(), 0, 1, 1)
	f.admitted(t, used, t.Context(), 0, 2, 2)
	old := replaceImageTestPeer(t, f, used, unused, alias)
	runtime.GC()
	require(t, old.Value() == nil, "retained round and untaken result keep the old peer alive")
	requireImageTake(t, used, t.Context(), 2, expectedImageQuery(2, 2), errImageDisconnected, "retained outcome after old peer collection")
	runtime.KeepAlive(unused)
	runtime.KeepAlive(alias)
}

func replaceImageTestPeer(t *testing.T, f *imageTestFixture, used, unused, alias *ImageRound) weak.Pointer[peer] {
	t.Helper()
	old := f.peers[0]
	f.s.unregisterPeer(old)
	newer := f.addSession(t, f.ids[0], "192.0.2.81:9")
	replacement := f.round(t, imageTestLimits(), newer)
	f.admitted(t, replacement, t.Context(), newer, 1, 1)
	f.refused(t, unused, t.Context(), 0, 3, errImageDisconnected)
	f.refusedDropping(t, alias, t.Context(), "192.0.2.40:9", 0, 3, imageTestByteLimit, errImageDisconnected, imageDrop{})
	f.s.unregisterPeer(old)
	f.refused(t, replacement, t.Context(), newer, 1, errImageAssignmentCurrent)
	requireImageTake(t, used, t.Context(), 1, expectedImageQuery(1, 1), errImageDisconnected, "recorded old end after repeated exit")
	req := f.lockRequester()
	detached := old.imageSession.lastID == 0
	_, indexed := req.sessions[old.imageSession]
	req.mu.Unlock()
	require(t, detached, "old session still owns its allocator")
	require(t, !indexed, "old session remains in the live requester registry")
	f.peers[0] = nil
	return weak.Make(old)
}

func testImageExitBeforeCapture(t *testing.T) {
	f := newImageTestFixture(t, 1)
	p := f.peers[0]
	release := sync.OnceFunc(f.s.lockPeerQuotaKey(p.daQuotaIdentity))
	defer release()
	done := make(chan struct{})
	go func() { defer close(done); f.s.unregisterPeer(p) }()
	waitForPeerQuotaLockRefs(t, f.s, p.daQuotaIdentity, 2)
	reads := f.clock.readCount()
	f.requireRoundRefused(t, t.Context(), f.config(imageTestLimits(), 0), errImageSourceSet, "first capture during exit cleanup")
	config := imageProbeConfig(f, f.clock.add(0), imageTestLimits(), 0)
	checkImageProbeBegin(t, f, t.Context(), config, errImageSourceSet)
	requireEqual(t, f.clock.readCount(), reads, "clock reads for retired source constructors")
	req := f.lockRequester()
	created := p.imageSession != nil || len(req.sessions) != 0
	req.mu.Unlock()
	require(t, !created, "retired source acquired a registration identity")
	release()
	requireChannelClosed(t, done, "peer cleanup")
}

func testImageRetirementBetweenSnapshotAndCapture(t *testing.T) {
	t.Run("round", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		limits := imageTestLimits()
		config := f.config(limits, 0, 1)
		beginImageDuringSourceRetirement(t, f, "BeginImageRound", func() (*ImageRound, error) {
			return f.s.BeginImageRound(t.Context(), config)
		})
		round := f.round(t, limits, 1)
		requireImageResult(t, f.request(round, t.Context(), 1, 1), 1, 1, nil, "request after refused capture")
		f.requireNoRetiredImageIdentity(t)
	})
	t.Run("probe round", func(t *testing.T) {
		f := newImageTestFixture(t, 2)
		limits, now := imageTestLimits(), f.clock.add(0)
		config := imageProbeConfig(f, now, limits, 0, 1)
		beginImageDuringSourceRetirement(t, f, "BeginImageProbeRound", func() (*ImageRound, error) {
			return f.s.BeginImageProbeRound(t.Context(), config)
		})
		round := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, now, limits, 1), nil)
		checkImageProbe(t, round, t.Context(), f.ids[1], 1, imageTestByteLimit, [32]byte{}, expectedImageQuery(1, 1), nil)
		f.requireNoRetiredImageIdentity(t)
	})
}

func beginImageDuringSourceRetirement(t *testing.T, f *imageTestFixture, constructor string, begin func() (*ImageRound, error)) {
	t.Helper()
	req := f.lockRequester()
	release := sync.OnceFunc(req.mu.Unlock)
	defer release()
	leases := f.leases()
	started := make(chan imageBegin, 1)
	go func() {
		round, err := begin()
		started <- imageBegin{round: round, err: err}
	}()
	waitUntil(t, func() bool {
		return f.leases() == leases+1 && goroutineParked("[sync.Mutex.Lock", "p2p.(*Service)."+constructor+"(")
	}, "constructor mutex wait after the live source snapshot")
	f.peers[0].imageRetired.Store(true)
	release()
	got := awaitImageResult(t, started, "constructor after source retirement")
	requireEqual(t, got.err, errImageSourceSet, "constructor error after source retirement")
	requireEqual(t, got.round, (*ImageRound)(nil), "constructor result after source retirement")
}

func (f *imageTestFixture) requireNoRetiredImageIdentity(t *testing.T) {
	t.Helper()
	req := f.lockRequester()
	identity, sessions := f.peers[0].imageSession, len(req.sessions)
	req.mu.Unlock()
	requireEqual(t, identity, (*imageSession)(nil), "retired registration identity")
	requireEqual(t, sessions, 1, "captured live registration count")
}

func testImageRetiredSourceAllocations(t *testing.T) {
	const liveIndex = 5
	f := newImageTestFixture(t, liveIndex+1)
	for _, p := range f.peers[:liveIndex] {
		done := make(chan struct{})
		t.Cleanup(func() { requireChannelClosed(t, done, "retired peer cleanup") })
		holdPeerExit(t, f.s, p.addr())
		go func() { defer close(done); f.s.unregisterPeer(p) }()
		waitForPeerQuotaLockRefs(t, f.s, p.daQuotaIdentity, 2)
	}
	f.s.peersMu.RLock()
	mapped := len(f.s.peers)
	f.s.peersMu.RUnlock()
	requireEqual(t, mapped, 12, "mapped identifiers during peer cleanup")
	ctx := t.Context()
	t.Run("round", func(t *testing.T) {
		config := f.config(imageTestLimits(), 0)
		requireImageSourceRefusalNoAlloc(t, "retired source constructor", func() (*ImageRound, error) {
			return f.s.BeginImageRound(ctx, config)
		})
	})
	t.Run("probe round", func(t *testing.T) {
		config := imageProbeConfig(f, f.clock.add(0), imageTestLimits(), 0)
		requireImageSourceRefusalNoAlloc(t, "retired source constructor", func() (*ImageRound, error) {
			return f.s.BeginImageProbeRound(ctx, config)
		})
	})
	t.Run("live identifier bound", func(t *testing.T) {
		config := f.config(imageTestLimits(), liveIndex)
		config.SourceIDs = slices.Repeat(config.SourceIDs, 9)
		requireImageSourceRefusalNoAlloc(t, "live identifier bound", func() (*ImageRound, error) {
			return f.s.BeginImageRound(ctx, config)
		})
	})
	round := f.round(t, imageTestLimits(), liveIndex)
	requireImageResult(t, f.request(round, ctx, liveIndex, 1), 1, 1, nil, "request on the live registration")
	probe := checkImageProbeBegin(t, f, ctx, imageProbeConfig(f, f.clock.add(0), imageTestLimits(), liveIndex), nil)
	checkImageProbe(t, probe, ctx, f.ids[liveIndex], 2, imageTestByteLimit, [32]byte{0x42}, expectedImageQuery(2, 2), nil)
	f.requireFrames(t, liveIndex, "live registration frames", expectedImageQuery(1, 1), expectedImageQuery(2, 2))
}

func requireImageSourceRefusalNoAlloc(t *testing.T, label string, begin func() (*ImageRound, error)) {
	t.Helper()
	var got imageBegin
	allocations := testing.AllocsPerRun(100, func() { got.round, got.err = begin() })
	requireEqual(t, got, imageBegin{err: errImageSourceSet}, label)
	requireEqual(t, allocations, 0, label+" allocations")
}

func testImageLiveSourceBound(t *testing.T) {
	f := newImageTestFixture(t, 2)
	alias := strings.Repeat("x", 32<<20)
	f.s.peersMu.Lock()
	f.s.peers[alias] = f.peers[1]
	f.s.peersMu.Unlock()
	retired := f.peers[0]
	release := sync.OnceFunc(f.s.lockPeerQuotaKey(retired.daQuotaIdentity))
	defer release()
	done := make(chan struct{})
	go func() { defer close(done); f.s.unregisterPeer(retired) }()
	waitForPeerQuotaLockRefs(t, f.s, retired.daQuotaIdentity, 2)
	requireEqual(t, f.serviceEntry(f.ids[0]), retired, "retired peer's logical name during cleanup")
	requireEqual(t, f.serviceEntry("192.0.2.40:9"), retired, "retired peer's alias during cleanup")
	config := f.config(imageTestLimits(), 1)
	config.SourceIDs = []string{alias, alias, alias, alias}
	f.s.peersMu.RLock()
	raw := len(f.s.peers)
	f.s.peersMu.RUnlock()
	requireEqual(t, raw, 5, "mapped sources with two retired names")
	requireBoundedImageSourceRefusal(t, f, config, alias)
	release()
	requireChannelClosed(t, done, "retired source cleanup")
}

func requireBoundedImageSourceRefusal(t *testing.T, f *imageTestFixture, config ImageRoundConfig, alias string) {
	t.Helper()
	begin := func() (*ImageRound, error) { return f.s.BeginImageRound(t.Context(), config) }
	denied, allocated := measureImageBeginAllocation(begin)
	requireEqual(t, denied, imageBegin{err: errImageSourceSet}, "more identifiers than live entries")
	size := uint64(len(alias))
	require(t, allocated < size/4, "overbound list allocated %d bytes for a %d-byte alias", allocated, size)
	config.SourceIDs = []string{alias}
	admitted, allocated := measureImageBeginAllocation(begin)
	must(t, admitted.err, "one live alias")
	require(t, admitted.round != nil && allocated >= size, "eligible alias allocated %d bytes, need a reachable %d-byte copy", allocated, size)
	got := requestWithin(lifecycleWatchdog, admitted.round, t.Context(), alias, 1, imageTestByteLimit)
	requireImageResult(t, got, 1, 1, nil, "request through the long live alias")
}

func measureImageBeginAllocation(begin func() (*ImageRound, error)) (imageBegin, uint64) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	round, err := begin()
	runtime.ReadMemStats(&after)
	return imageBegin{round: round, err: err}, after.TotalAlloc - before.TotalAlloc
}

func imageProbeConfig(f *imageTestFixture, base time.Time, limits ImageLimits, sessions ...int) ImageProbeRoundConfig {
	config := f.config(limits, sessions...)
	return ImageProbeRoundConfig{
		Anchor: config.Anchor, SourceIDs: config.SourceIDs, Limits: limits,
		BodyAdmissionTime: base, BodyRD: base.Add(100 * time.Second),
	}
}

func checkImageProbeBegin(t *testing.T, f *imageTestFixture, ctx context.Context, config ImageProbeRoundConfig, want error) *ImageRound {
	t.Helper()
	got := callWithin(t, "BeginImageProbeRound", func() imageBegin {
		round, err := f.s.BeginImageProbeRound(ctx, config)
		return imageBegin{round: round, err: err}
	})
	requireEqual(t, got.err, want, "probe round constructor error")
	requireEqual(t, got.round != nil, want == nil, "probe constructor result presence")
	return got.round
}

func launchImageProbe(round *ImageRound, ctx context.Context, source string, start byte, limit uint32, hash [32]byte) <-chan imageResult {
	done := make(chan imageResult, 1)
	go func() {
		q, err := round.Probe(ctx, source, imageStart(start), limit, hash)
		done <- imageResult{q: q, err: err}
	}()
	return done
}

func checkImageProbe(t *testing.T, round *ImageRound, ctx context.Context, source string, start byte, limit uint32, hash [32]byte, q consensus.UTXOImageQuery, want error) {
	t.Helper()
	got := awaitImageResult(t, launchImageProbe(round, ctx, source, start, limit, hash), "Probe")
	requireQueryResult(t, got, q, want, "probe result")
}

func requireProbeRefusal(t *testing.T, f *imageTestFixture, round *ImageRound, source int, start byte, limit uint32, want error) {
	t.Helper()
	before := f.snapshot(round, source)
	checkImageProbe(t, round, t.Context(), f.ids[source], start, limit, [32]byte{}, consensus.UTXOImageQuery{}, want)
	requireEqual(t, f.snapshot(round, source), before, "probe refusal effects")
}

func testImageProbeDeadlines(t *testing.T) {
	t.Run("attempt starts date their own deadlines", testImageProbeOwnStarts)
	t.Run("capped deadline stays current at RD", testImageProbeCappedDeadline)
	t.Run("request count stays spent", func(t *testing.T) { testImageProbeWindow(t, false) })
	t.Run("distinct starts stay spent", func(t *testing.T) { testImageProbeWindow(t, true) })
	t.Run("body hash does not enter the query", testImageProbeHashOutsideQuery)
}

func testImageProbeOwnStarts(t *testing.T) {
	f := newImageTestFixture(t, 2)
	base := f.clock.add(0)
	config := imageProbeConfig(f, base, imageTestLimits(), 0)
	before := f.clock.readCount()
	probe := checkImageProbeBegin(t, f, t.Context(), config, nil)
	requireEqual(t, f.clock.readCount(), before, "clock reads by probe constructor")
	other := f.round(t, imageTestLimits(80*time.Second), 1)
	q1, q2 := expectedImageQuery(1, 1), expectedImageQuery(2, 2)
	f.clock.set(base.Add(5 * time.Second))
	hash1, hash2 := [32]byte{}, [32]byte{0x73, 31: 0x9a}
	checkImageProbe(t, probe, t.Context(), f.ids[0], 1, imageTestByteLimit, hash1, q1, nil)
	first := f.instance(1)
	f.clock.set(base.Add(15 * time.Second))
	f.refused(t, other, t.Context(), 1, 1, errImageAssignmentCurrent)
	f.clock.add(time.Second)
	requireImageTake(t, probe, t.Context(), 1, q1, errImageExpired, "first attempt after its D")
	f.admitted(t, other, t.Context(), 1, 1, 1)
	f.clock.set(base.Add(20 * time.Second))
	checkImageProbe(t, probe, t.Context(), f.ids[0], 2, imageTestByteLimit, hash2, q2, nil)
	f.clock.set(base.Add(25 * time.Second))
	f.refused(t, other, t.Context(), 1, 2, errImageAssignmentCurrent)
	f.clock.set(base.Add(30 * time.Second))
	f.refused(t, other, t.Context(), 1, 2, errImageAssignmentCurrent)
	second := f.instance(2)
	require(t, first.round.probe && second.round.probe, "admitted assignments lost probe mode")
	requireEqual(t, first.expectedBodyHash, hash1, "first admitted hash after second probe")
	requireEqual(t, second.expectedBodyHash, hash2, "second admitted hash")
	f.clock.add(time.Second)
	requireImageTake(t, probe, t.Context(), 2, q2, errImageExpired, "second attempt after its D")
	f.requireFrames(t, 0, "probe wire tuples", q1, q2)
}

func testImageProbeCappedDeadline(t *testing.T) {
	f := newImageTestFixture(t, 2)
	base := f.clock.add(0)
	config := imageProbeConfig(f, base, imageTestLimits(), 0)
	config.BodyRD = base.Add(9 * time.Second)
	probe := checkImageProbeBegin(t, f, t.Context(), config, nil)
	other := f.round(t, imageTestLimits(), 1)
	f.clock.add(5 * time.Second)
	q := expectedImageQuery(1, 1)
	checkImageProbe(t, probe, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}, q, nil)
	f.clock.set(config.BodyRD)
	f.refused(t, other, t.Context(), 1, 1, errImageAssignmentCurrent)
	f.clock.add(time.Nanosecond)
	requireImageTake(t, probe, t.Context(), 1, q, errImageExpired, "one tick after capped deadline")
	f.admitted(t, other, t.Context(), 1, 1, 1)
	requireProbeRefusal(t, f, probe, 0, 2, imageTestByteLimit, errImageRoundDeadline)
}

func testImageProbeWindow(t *testing.T, distinct bool) {
	f := newImageTestFixture(t, 1)
	base := f.clock.add(0)
	limits := imageTestLimits()
	if distinct {
		limits.Global.DistinctStarts = 2
	} else {
		limits.Global.AdmittedRequests = 2
	}
	probe := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, base, limits, 0), nil)
	for i := byte(1); i <= 2; i++ {
		q := expectedImageQuery(uint64(i), i)
		checkImageProbe(t, probe, t.Context(), f.ids[0], i, imageTestByteLimit, [32]byte{i}, q, nil)
		f.clock.add(10*time.Second + 1)
		requireImageTake(t, probe, t.Context(), i, q, errImageExpired, "spent attempt")
	}
	requireProbeRefusal(t, f, probe, 0, 3, imageTestByteLimit, errImageLimit)
	ordinary := f.round(t, imageTestLimits(), 0)
	inst := f.admitted(t, ordinary, t.Context(), 0, 3, 3)
	require(t, !inst.round.probe && inst.expectedBodyHash == [32]byte{}, "ordinary assignment has a probe binding")
}

func testImageProbeHashOutsideQuery(t *testing.T) {
	for _, hash := range [][32]byte{{}, {0xff, 31: 0xbe}} {
		f := newImageTestFixture(t, 1)
		probe := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, f.clock.add(0), imageTestLimits(), 0), nil)
		q := expectedImageQuery(1, 8)
		checkImageProbe(t, probe, t.Context(), f.ids[0], 8, imageTestByteLimit, hash, q, nil)
		f.requireFrames(t, 0, "query independent of the body hash", q)
		requireEqual(t, f.instance(8).expectedBodyHash, hash, "exact instance hash")
	}
}

type imageProbeBeginCase struct {
	name   string
	want   error
	mutate func(*ImageProbeRoundConfig)
}

func testImageProbeConstructor(t *testing.T) {
	f := newImageTestFixture(t, 2)
	base := f.clock.add(0)
	for _, tc := range imageProbeBeginCases(f) {
		t.Run(tc.name, func(t *testing.T) {
			config := imageProbeConfig(f, base, imageTestLimits(), 0, 1)
			tc.mutate(&config)
			ctx := t.Context()
			if errors.Is(tc.want, errImageNilContext) {
				ctx = nil
			}
			checkImageProbeBegin(t, f, ctx, config, tc.want)
		})
	}
	checkImageProbeUnitRefusals(t, f, base)
	probe := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, base, imageTestLimits(), 0), nil)
	checkImageProbe(t, probe, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}, expectedImageQuery(1, 1), nil)
	t.Run("clock pairs", testImageProbeClockPairs)
}

func imageProbeBeginCases(f *imageTestFixture) []imageProbeBeginCase {
	return []imageProbeBeginCase{
		{"nil context before height", errImageNilContext, func(c *ImageProbeRoundConfig) { c.Anchor.Height = 0x100000000 }},
		{"height before limits", errImageRequestDomain, func(c *ImageProbeRoundConfig) { c.Anchor.Height, c.Limits.Backoff = 0x100000000, 0 }},
		{"zero attempt lifetime", errImagePolicy, func(c *ImageProbeRoundConfig) { c.Limits.AttemptLifetime = 0 }},
		{"negative attempt lifetime", errImagePolicy, func(c *ImageProbeRoundConfig) { c.Limits.AttemptLifetime = -1 }},
		{"zero round lifetime", errImagePolicy, func(c *ImageProbeRoundConfig) { c.Limits.RoundLifetime = 0 }},
		{"negative round lifetime", errImagePolicy, func(c *ImageProbeRoundConfig) { c.Limits.RoundLifetime = -1 }},
		{"zero backoff before sources", errImagePolicy, func(c *ImageProbeRoundConfig) { c.Limits.Backoff, c.SourceIDs = 0, nil }},
		{"negative backoff", errImagePolicy, func(c *ImageProbeRoundConfig) { c.Limits.Backoff = -1 }},
		{"admission after deadline", errImagePolicy, func(c *ImageProbeRoundConfig) { c.BodyRD = c.BodyAdmissionTime.Add(-1) }},
		{"monotonic admission and wall deadline", errImagePolicy, func(c *ImageProbeRoundConfig) {
			c.BodyAdmissionTime = time.Now()
			c.BodyRD = c.BodyAdmissionTime.Round(0).Add(time.Hour)
		}},
		{"wall admission and monotonic deadline", errImagePolicy, func(c *ImageProbeRoundConfig) {
			c.BodyRD = time.Now().Add(time.Hour)
			c.BodyAdmissionTime = c.BodyRD.Round(0).Add(-time.Hour)
		}},
		{"nil sources", errImageSourceSet, func(c *ImageProbeRoundConfig) { c.SourceIDs = nil }},
		{"empty sources", errImageSourceSet, func(c *ImageProbeRoundConfig) { c.SourceIDs = []string{} }},
		{"unknown source", errImageSourceSet, func(c *ImageProbeRoundConfig) { c.SourceIDs = []string{f.ids[0], "absent:9"} }},
		{"duplicate source", errImageSourceSet, func(c *ImageProbeRoundConfig) { c.SourceIDs = []string{f.ids[0], f.ids[0]} }},
		{"logical name and alias", errImageSourceSet, func(c *ImageProbeRoundConfig) { c.SourceIDs = []string{f.ids[0], "192.0.2.40:9"} }},
	}
}

func checkImageProbeUnitRefusals(t *testing.T, f *imageTestFixture, base time.Time) {
	t.Helper()
	fields := reflect.TypeFor[ImageUnits]()
	for i := range fields.NumField() {
		for _, side := range []string{"per peer", "global"} {
			t.Run("zero "+side+" "+fields.Field(i).Name, func(t *testing.T) {
				config := imageProbeConfig(f, base, imageTestLimits(), 0)
				units := &config.Limits.PerPeer
				if side == "global" {
					units = &config.Limits.Global
				}
				reflect.ValueOf(units).Elem().Field(i).SetUint(0)
				checkImageProbeBegin(t, f, t.Context(), config, errImagePolicy)
			})
		}
	}
}

func testImageProbeClockPairs(t *testing.T) {
	for _, tc := range []struct {
		name string
		now  time.Time
	}{{"wall pair", time.Unix(1_800_000_000, 0)}, {"monotonic pair", time.Now()}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageTestFixtureAt(t, 1, tc.now)
			config := imageProbeConfig(f, tc.now, imageTestLimits(), 0)
			equal := config
			equal.BodyRD = equal.BodyAdmissionTime
			probe := checkImageProbeBegin(t, f, t.Context(), equal, nil)
			requireProbeRefusal(t, f, probe, 0, 1, imageTestByteLimit, errImageRoundDeadline)
			f.clock.add(1)
			requireProbeRefusal(t, f, probe, 0, 1, imageTestByteLimit, errImageRoundDeadline)
			done, cancel := context.WithCancel(t.Context())
			cancel()
			canceled := checkImageProbeBegin(t, f, done, config, nil)
			checkImageProbe(t, canceled, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}, consensus.UTXOImageQuery{}, context.Canceled)
			valid := checkImageProbeBegin(t, f, t.Context(), config, nil)
			checkImageProbe(t, valid, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}, expectedImageQuery(1, 1), nil)
		})
	}
}

func testImageProbeEntryRefusals(t *testing.T) {
	t.Run("mode and wire domain", testImageProbeModeAndDomain)
	t.Run("start clock domain", testImageProbeSampleDomain)
	t.Run("inexact sum before the cutoff", testImageProbeInexactDeadline)
	t.Run("unit refusal before exhausted ID", testImageProbeUnitsBeforeID)
}

func testImageProbeModeAndDomain(t *testing.T) {
	f, ordinary := newImageRound(t, 2, 0)
	base := f.clock.add(0)
	limits := imageTestLimits()
	limits.Global.AdmittedRequests = 2
	probe := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, base, limits, 0, 1), nil)
	for _, limit := range []uint32{imageTestByteLimit, 150904} {
		requireProbeRefusal(t, f, ordinary, 0, 1, limit, errImageRoundMode)
		f.refusedDropping(t, probe, t.Context(), f.ids[0], 0, 1, limit, errImageRoundMode, imageDrop{})
	}
	for _, limit := range []uint32{150904, 2097153} {
		requireProbeRefusal(t, f, probe, 0, 1, limit, errImageRequestDomain)
	}
	q1, q2 := expectedImageQuery(1, 1), expectedImageQuery(2, 2)
	q1.ByteLimit, q2.ByteLimit = 150905, 2097152
	checkImageProbe(t, probe, t.Context(), f.ids[0], 1, q1.ByteLimit, [32]byte{}, q1, nil)
	checkImageProbe(t, probe, t.Context(), f.ids[0], 2, q2.ByteLimit, [32]byte{}, q2, nil)
	requireProbeRefusal(t, f, probe, 1, 3, imageTestByteLimit, errImageLimit)
	f.requireFrames(t, 0, "wire-domain boundaries", q1, q2)
}

func testImageProbeSampleDomain(t *testing.T) {
	base := time.Now()
	f := newImageTestFixtureAt(t, 1, base.Round(0))
	config := imageProbeConfig(f, base, imageTestLimits(), 0)
	config.Limits.Global.AdmittedRequests = 1
	probe := checkImageProbeBegin(t, f, t.Context(), config, nil)
	requireProbeRefusal(t, f, probe, 0, 1, imageTestByteLimit, errImagePolicy)
	config.BodyRD = config.BodyAdmissionTime
	atCutoff := checkImageProbeBegin(t, f, t.Context(), config, nil)
	checkImageProbe(t, atCutoff, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}, consensus.UTXOImageQuery{}, errImagePolicy)
	f.clock.set(base)
	checkImageProbe(t, probe, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}, expectedImageQuery(1, 1), nil)
	requireProbeRefusal(t, f, probe, 0, 2, imageTestByteLimit, errImageLimit)
}

func testImageProbeInexactDeadline(t *testing.T) {
	base := time.Now()
	f := newImageTestFixtureAt(t, 1, base)
	config := imageProbeConfig(f, base, imageTestLimits(time.Duration(math.MaxInt64)), 0)
	probe := checkImageProbeBegin(t, f, t.Context(), config, nil)
	requireProbeRefusal(t, f, probe, 0, 1, imageTestByteLimit, errImagePolicy)
	f.clock.add(time.Nanosecond)
	requireProbeRefusal(t, f, probe, 0, 1, imageTestByteLimit, errImagePolicy)
	config.Limits.AttemptLifetime = 10 * time.Second
	valid := checkImageProbeBegin(t, f, t.Context(), config, nil)
	checkImageProbe(t, valid, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}, expectedImageQuery(1, 1), nil)
}

func testImageProbeUnitsBeforeID(t *testing.T) {
	f := newImageTestFixture(t, 2)
	base := f.clock.add(0)
	limits := imageTestLimits()
	limits.PerPeer.AdmittedRequests = 1
	limits.Global.AdmittedRequests = 2
	probe := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, base, limits, 0, 1), nil)
	ctx := newImageHookCtx()
	checkImageProbe(t, probe, ctx, f.ids[0], 1, imageTestByteLimit, [32]byte{}, expectedImageQuery(1, 1), nil)
	ctx.end(errImageRequestEnd)
	requireImageTake(t, probe, t.Context(), 1, expectedImageQuery(1, 1), errImageRequestEnd, "first probe ends before capacity refusal")
	f.setLastID(0, math.MaxUint64)
	requireProbeRefusal(t, f, probe, 0, 2, imageTestByteLimit, errImageLimit)
	fresh := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, base, limits, 0), nil)
	requireProbeRefusal(t, f, fresh, 0, 2, imageTestByteLimit, errImageIDExhausted)
	checkImageProbe(t, probe, t.Context(), f.ids[1], 2, imageTestByteLimit, [32]byte{}, expectedImageQuery(1, 2), nil)
}

func testImageTerminalEntryPriority(t *testing.T) {
	t.Run("closed round and contexts", testImageClosedRoundEntryPriority)
	t.Run("retired and unlisted source", testImageSourceEntryPriority)
}

type imageEarlyRefusalCase struct {
	name       string
	want       error
	probeRound bool
	probeCall  bool
}

func testImageEarlyRefusalPreservesEnd(t *testing.T) {
	for _, tc := range []imageEarlyRefusalCase{
		{name: "request on closed round", want: errImageRoundClosed},
		{name: "probe on closed round", want: errImageRoundClosed, probeRound: true, probeCall: true},
		{name: "request to retired source", want: errImageDisconnected},
		{name: "probe to retired source", want: errImageDisconnected, probeRound: true, probeCall: true},
		{name: "request on probe round", want: errImageRoundMode, probeRound: true},
		{name: "probe on ordinary round", want: errImageRoundMode, probeCall: true},
	} {
		t.Run(tc.name, func(t *testing.T) { checkImageEarlyRefusalEnd(t, tc) })
	}
}

func checkImageEarlyRefusalEnd(t *testing.T, tc imageEarlyRefusalCase) {
	f := newImageTestFixture(t, 2)
	sibling := f.round(t, imageTestLimits(time.Hour, 2*time.Hour), 1)
	ctx := newImageHookCtx()
	f.admitted(t, sibling, ctx, 1, 2, 1)
	limits := imageTestLimits(2*time.Hour, 3*time.Hour)
	var target *ImageRound
	if tc.probeRound {
		base := f.clock.add(0)
		config := imageProbeConfig(f, base, limits, 0)
		config.BodyRD = base.Add(3 * time.Hour)
		target = checkImageProbeBegin(t, f, t.Context(), config, nil)
	} else {
		target = f.round(t, limits, 0)
	}
	switch {
	case errors.Is(tc.want, errImageRoundClosed):
		target.Close()
	case errors.Is(tc.want, errImageDisconnected):
		f.s.unregisterPeer(f.peers[0])
	}
	f.clock.add(time.Hour + 1)
	if tc.probeCall {
		checkImageProbe(t, target, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}, consensus.UTXOImageQuery{}, tc.want)
	} else {
		requireQueryResult(t, f.request(target, t.Context(), 0, 1), consensus.UTXOImageQuery{}, tc.want, "early request refusal")
	}
	ctx.end(errImageRequestEnd)
	requireImageTake(t, sibling, t.Context(), 2, expectedImageQuery(1, 2), errImageRequestEnd, "first observed end after unrelated refusal")
	requireImageAbsent(t, sibling, t.Context(), 2, errImageNoAssignment)
}

func testImageClosedRoundEntryPriority(t *testing.T) {
	f := newImageTestFixture(t, 1)
	ctx, owner := newImageHookCtx(), newImageHookCtx()
	round := f.roundCtx(t, owner, imageTestLimits(), 0)
	round.Close()
	owner.end(errImageRoundEnd)
	ctx.end(errImageRequestEnd)
	for _, tc := range []struct {
		ctx  context.Context
		want error
	}{{nil, errImageNilContext}, {ctx, errImageRequestEnd}, {t.Context(), errImageRoundEnd}} {
		f.refusedDropping(t, round, tc.ctx, "unknown:1", 0, 1, 150904, tc.want, imageDrop{})
		checkImageProbe(t, round, tc.ctx, "unknown:1", 1, 150904, [32]byte{}, consensus.UTXOImageQuery{}, tc.want)
	}
	requireImageAbsent(t, round, nil, 1, errImageNilContext)
	requireImageAbsent(t, round, ctx, 1, errImageRoundClosed)
	live := f.round(t, imageTestLimits(), 0)
	live.Close()
	f.refusedDropping(t, live, t.Context(), "unknown:1", 0, 1, 150904, errImageRoundClosed, imageDrop{})
	checkImageProbe(t, live, t.Context(), "unknown:1", 1, 150904, [32]byte{}, consensus.UTXOImageQuery{}, errImageRoundClosed)
	next := f.round(t, imageTestLimits(), 0)
	f.admitted(t, next, t.Context(), 0, 1, 1)
}

func testImageSourceEntryPriority(t *testing.T) {
	f, ordinary := newImageRound(t, 2, 0, 1)
	probe := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, f.clock.add(0), imageTestLimits(), 0, 1), nil)
	f.s.unregisterPeer(f.peers[0])
	requireProbeRefusal(t, f, ordinary, 0, 1, 150904, errImageDisconnected)
	f.refusedDropping(t, probe, t.Context(), f.ids[0], 0, 1, 150904, errImageDisconnected, imageDrop{})
	checkImageProbe(t, probe, t.Context(), "192.0.2.41:9", 1, 150904, [32]byte{}, consensus.UTXOImageQuery{}, errImageUnknownSource)
	f.refusedDropping(t, ordinary, t.Context(), "192.0.2.41:9", 1, 1, 150904, errImageUnknownSource, imageDrop{})
	checkImageProbe(t, probe, t.Context(), f.ids[1], 1, imageTestByteLimit, [32]byte{}, expectedImageQuery(1, 1), nil)
}

func testImageProbeDrain(t *testing.T) {
	t.Run("draining beats the held sample", testImageProbeDrainAtSample)
	t.Run("open sample wins before draining", testImageProbeDrainAfterSample)
}

func testImageProbeDrainAtSample(t *testing.T) {
	f := newImageTestFixture(t, 2)
	config := imageProbeConfig(f, f.clock.add(0), imageTestLimits(), 0)
	probe := checkImageProbeBegin(t, f, t.Context(), config, nil)
	other := f.round(t, imageTestLimits(), 1)
	writeEntered, releaseWrite := f.holdImageFrame(t, 1, func() {})
	defer releaseWrite()
	write := f.goRequest(other, t.Context(), 1, 2)
	requireChannelClosed(t, writeEntered, "independent writer")
	before := f.owners(probe, 0)
	requireEqual(t, before, imageOwners{ids: 1, current: 1, idKeys: 1}, "owner state before the probe sample")
	entered, release := f.blockNextRead(func(now time.Time) time.Time { return now }, func() {})
	send := launchImageProbe(probe, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{0x42})
	closed := f.closeWhileReadHeld(t, entered, release)
	requireQueryResult(t, awaitImageResult(t, send, "probe stopped by drain"), consensus.UTXOImageQuery{}, errServiceClosed, "probe stopped by drain")
	requireChannelClosed(t, f.conns[1].closed, "independent connection close during drain")
	requireStillBlocked(t, closed, "Close while independent writer is held")
	f.requireOwners(t, probe, 0, before, "drain-won admission effects before Close returns")
	requireEqual(t, f.lastID(0), uint64(0), "probe source ID before Close returns")
	releaseWrite()
	requireImageResult(t, awaitImageResult(t, write, "independent writer after drain"), 1, 2, net.ErrClosed, "independent writer after drain")
	requireReturned(t, closed, "Close")
	requireEqual(t, f.owners(probe, 0), imageOwners{}, "drain-won admission effects")
	f.requireFrames(t, 0, "drain-won probe")
	config.Anchor.Height, config.Limits.Backoff, config.SourceIDs = math.MaxUint64, 0, nil
	checkImageProbeBegin(t, f, nil, config, errServiceClosed)
	checkImageProbe(t, probe, nil, "unknown:9", 1, 150904, [32]byte{}, consensus.UTXOImageQuery{}, errServiceClosed)
	fresh := newImageTestFixture(t, 1)
	valid := checkImageProbeBegin(t, fresh, t.Context(), imageProbeConfig(fresh, fresh.clock.add(0), imageTestLimits(), 0), nil)
	checkImageProbe(t, valid, t.Context(), fresh.ids[0], 1, imageTestByteLimit, [32]byte{0x42}, expectedImageQuery(1, 1), nil)
}

func testImageProbeDrainAfterSample(t *testing.T) {
	f := newImageTestFixture(t, 1)
	probe := checkImageProbeBegin(t, f, t.Context(), imageProbeConfig(f, f.clock.add(0), imageTestLimits(), 0), nil)
	ctx, entered, gate := newImageHookCtx(), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	ctx.onSecondErr = func() { close(entered); <-gate }
	send := launchImageProbe(probe, ctx, f.ids[0], 1, imageTestByteLimit, [32]byte{0x42})
	requireChannelClosed(t, entered, "probe operation context recheck after OPEN")
	closed := lifecycleClose(f.s)
	requireChannelClosed(t, f.conns[0].closed, "connection close during probe drain")
	requireStillBlocked(t, closed, "Close while probe admission is held")
	release()
	requireImageResult(t, awaitImageResult(t, send, "probe authorized before drain"), 1, 1, net.ErrClosed, "probe authorized before drain")
	requireReturned(t, closed, "Close after probe")
	f.requireOwners(t, probe, 0, imageJoinedOwners(imageOneInstance(0)), "admitted work at Close return")
	attempted, _ := f.conns[0].snapshot()
	requireEqual(t, len(attempted), wireHeaderSize, "actual write attempted after OPEN admission")
	f.requireFault(t, 0, 2, net.ErrClosed.Error(), "transport error remains visible")
}

func testImageProbeBeforeWrite(t *testing.T) {
	t.Run("RD reached under writeMu", testImageProbeWriteAtRD)
	for _, tc := range []struct {
		name string
		at   time.Duration
		rd   time.Duration
		want error
	}{{"one tick after D", 10*time.Second + 1, 100 * time.Second, errImageExpired}, {"at RD", 5 * time.Second, 5 * time.Second, errImageRoundDeadline}} {
		t.Run(tc.name, inImageBubble(func(t *testing.T) {
			f := newImageTestFixture(t, 1)
			base := f.clock.add(0)
			config := imageProbeConfig(f, base, imageTestLimits(), 0)
			config.BodyRD = base.Add(tc.rd)
			probe := checkImageProbeBegin(t, f, t.Context(), config, nil)
			release := f.holdWrite(t, 0)
			pending := launchImageProbe(probe, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{})
			synctest.Wait()
			f.waitAdmitted(t, 0, 1, "probe waiting for writeMu")
			f.clock.set(base.Add(tc.at))
			requireImageResult(t, awaitImageResult(t, pending, "probe presend refusal"), 1, 1, tc.want, "probe presend refusal")
			requireImageAbsent(t, probe, t.Context(), 1, errImageNoAssignment)
			must(t, release(), "holder write")
			f.requireFrames(t, 0, "presend refusal")
			f.requireUsage(t, probe, 0, imageUsage(0, 1, 1, 1, 0), imageUsage(0, 1, 1, 1, 0), "consumed probe units")
		}))
	}
}

func testImageProbeWriteAtRD(t *testing.T) {
	f := newImageTestFixture(t, 1)
	base := f.clock.add(0)
	config := imageProbeConfig(f, base, imageTestLimits(), 0)
	config.BodyRD = base.Add(5 * time.Second)
	probe := checkImageProbeBegin(t, f, t.Context(), config, nil)
	f.clock.onReadFrom(".(*ImageRound).endBeforeWrite", func(time.Time) time.Time { return config.BodyRD })
	got := awaitImageResult(t, launchImageProbe(probe, t.Context(), f.ids[0], 1, imageTestByteLimit, [32]byte{}), "probe checked under writeMu")
	f.requireFrames(t, 0, "frames at the exclusive send cutoff")
	requireImageResult(t, got, 1, 1, errImageRoundDeadline, "probe checked under writeMu")
}
