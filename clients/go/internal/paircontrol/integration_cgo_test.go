//go:build cgo && (darwin || linux) && (amd64 || arm64)

package paircontrol

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

// waitContext uses the same public-context checkpoint as the existing native
// serving tests: Done is reached only at the actual cancellation wait select.
type waitContext struct {
	context.Context
	waiting, resume chan struct{}
	signal          sync.Once
}

func (c *waitContext) Done() <-chan struct{} {
	c.signal.Do(func() { close(c.waiting) })
	<-c.resume
	return c.Context.Done()
}

func TestActualNativeQuiescenceRetirementJoin(t *testing.T) {
	p, i := h1Policy(t)
	s, dir := existing(t, selected())
	r, err := s.PersistIntentV1(context.Background(), 17, i, p)
	require(t, err)
	if r != (ResultV1{2, 18, false}) {
		t.Fatal("actual P INTENT did not admit outer intent")
	}
	native, err := mdbx.Create(filepath.Join(t.TempDir(), "native"), mdbx.ConfigV1{
		Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20,
		Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492,
	})
	require(t, err)
	t.Cleanup(func() { require(t, native.Close()) })
	owner, err := mdbx.NewServingViewOwnerV1(time.Hour)
	require(t, err)
	reservations, err := mdbx.NewOperationReservationOwner(805306368)
	require(t, err)
	borrowed, releaseBorrow, viewDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resumeBorrow := sync.OnceFunc(func() { close(releaseBorrow) })
	var viewErr error
	go func() {
		defer close(viewDone)
		viewErr = reservations.WithOperation(mdbx.LaneOperation, func(a *mdbx.OperationAccount) error {
			_, err := owner.WithViewV1(context.Background(), native, a, func(_ *mdbx.Reader, _ *mdbx.ServingEpochV1) error {
				close(borrowed)
				<-releaseBorrow
				return nil
			})
			return err
		})
	}()
	t.Cleanup(func() {
		resumeBorrow()
		await(t, viewDone)
	})
	await(t, borrowed)
	o := installFaults(t, s)
	o.block, o.entered, o.resume = "write:outer-control.scratch", make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	wait := &waitContext{Context: ctx, waiting: make(chan struct{}), resume: make(chan struct{})}
	resumeWait := sync.OnceFunc(func() { close(wait.resume) })
	resumeOuter := sync.OnceFunc(func() { close(o.resume) })
	var retireErr error
	var retirement ResultV1
	go func() {
		defer close(done)
		retireErr = owner.WithQuiescenceV1(wait, native, func() error {
			if err := native.Close(); err != nil {
				return err
			}
			retirement, err = s.RetireV1(context.Background(), 18, i.ID, reference(), p)
			return err
		})
	}()
	t.Cleanup(func() {
		cancel()
		resumeBorrow()
		resumeWait()
		resumeOuter()
		await(t, done)
	})
	await(t, wait.waiting)
	select {
	case <-o.entered:
		t.Fatal("control retirement crossed before actual serving last use")
	default:
	}
	resumeBorrow()
	await(t, viewDone)
	require(t, viewErr)
	resumeWait()
	await(t, o.entered)
	if tx, err := p.Begin(); tx != nil || !errors.Is(err, policycontrol.ErrBusy) {
		t.Fatal("P admission escaped before actual control write/cleanup")
	}
	resumeOuter()
	await(t, done)
	require(t, retireErr)
	if retirement != (ResultV1{2, 19, false}) {
		t.Fatal("joined retirement truth differs")
	}
	v := selected()
	v.Sequence, v.Selector, v.Selected, v.Intent = 19, 3, nil, &i
	v.Retired = &RetirementV1{originalPair(), 2, reference()}
	wantRecord(t, s, v)
	require(t, s.CloseV1())
	s, err = OpenV1(dir, identity())
	require(t, err)
	wantRecord(t, s, v)
	require(t, s.CloseV1())
}

func TestPReservationThroughEachOuterOperation(t *testing.T) {
	for _, operation := range []string{"persist_intent", "retire", "end_h1"} {
		t.Run(operation, func(t *testing.T) {
			p, i := h1Policy(t)
			s, dir := existing(t, selected())
			expected := uint64(17)
			if operation != "persist_intent" {
				_, err := s.PersistIntentV1(context.Background(), 17, i, p)
				require(t, err)
				expected = 18
			}
			if operation == "end_h1" {
				terminalPolicy(t, p, i, "blocked")
			}
			o := installFaults(t, s)
			o.block, o.entered, o.resume = "write:outer-control.scratch", make(chan struct{}), make(chan struct{})
			resume := sync.OnceFunc(func() { close(o.resume) })
			done := make(chan struct{})
			var result ResultV1
			var outerErr error
			go func() {
				defer close(done)
				switch operation {
				case "persist_intent":
					result, outerErr = s.PersistIntentV1(context.Background(), expected, i, p)
				case "retire":
					result, outerErr = s.RetireV1(context.Background(), expected, i.ID, reference(), p)
				case "end_h1":
					result, outerErr = s.EndH1V1(context.Background(), expected, i.ID, p)
				}
			}()
			t.Cleanup(func() {
				resume()
				await(t, done)
			})
			await(t, o.entered)
			if tx, err := p.Begin(); tx != nil || !errors.Is(err, policycontrol.ErrBusy) {
				t.Fatal("dependent writer reservation absent")
			}
			if _, err := p.PersistLatch(policycontrol.LatchProof{}); !errors.Is(err, policycontrol.ErrBusy) {
				t.Fatal("P latch intervened during outer crossing")
			}
			if _, err := p.Recover(); !errors.Is(err, policycontrol.ErrBusy) {
				t.Fatal("P recovery intervened during outer crossing")
			}
			if err := p.Close(); !errors.Is(err, policycontrol.ErrBusy) {
				t.Fatal("P closed during outer crossing")
			}
			if p.Gate().DependentEffects {
				t.Fatal("held-span Gate is not false")
			}
			if _, err := p.View(); err != nil {
				t.Fatal("ordinary detached P observation was incorrectly gated")
			}
			if _, err := s.ObserveV1(); !localCode(err, "observe", "busy") {
				t.Fatal("competing outer observation waited/admitted")
			}
			if _, err := s.RecoverV1(); !localCode(err, "recover", "busy") {
				t.Fatal("competing outer recovery admitted")
			}
			if err := s.CloseV1(); !localCode(err, "close", "busy") {
				t.Fatal("competing outer Close consumed live owner")
			}
			for _, call := range []func() (ResultV1, error){
				func() (ResultV1, error) { return s.PersistIntentV1(context.Background(), expected, i, p) },
				func() (ResultV1, error) { return s.RetireV1(context.Background(), expected, i.ID, reference(), p) },
				func() (ResultV1, error) {
					return s.RecordDamageV1(context.Background(), expected, originalPair(), reference())
				},
				func() (ResultV1, error) { return s.EndH1V1(context.Background(), expected, i.ID, p) },
			} {
				r, err := call()
				var e *ErrorV1
				if r != (ResultV1{}) || !errors.As(err, &e) || e.Code != "busy" {
					t.Fatal("competing mutator crossed or waited")
				}
			}
			resume()
			await(t, done)
			require(t, outerErr)
			if result != (ResultV1{2, expected + 1, false}) {
				t.Fatal("Gate false was reused as secondary consumer refusal")
			}
			want := selected()
			want.Sequence = expected + 1
			if operation != "end_h1" {
				want.Intent = &i
			}
			if operation == "retire" {
				want.Selector, want.Selected = 3, nil
				want.Retired = &RetirementV1{originalPair(), 2, reference()}
			}
			wantRecord(t, s, want)
			require(t, s.CloseV1())
			fresh, err := OpenV1(dir, identity())
			require(t, err)
			wantRecord(t, fresh, want)
			require(t, fresh.CloseV1())
			tx, err := p.Begin()
			require(t, err)
			_, err = tx.Abort()
			require(t, err)
		})
	}
}

func localCode(err error, operation, code string) bool {
	var e *ErrorV1
	return errors.As(err, &e) && e.Operation == operation && e.Code == code
}
