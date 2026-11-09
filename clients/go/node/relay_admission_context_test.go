package node

import (
	"math"
	"runtime"
	"strings"
	"testing"
	"time"
)

// relayObserverLiveness bounds every wait in this file. It is a liveness
// failure bound only: no assertion depends on a schedule completing within it.
const relayObserverLiveness = 5 * time.Second

type relayObservation struct {
	ctx PendingOutpointAdmissionContext
	ok  bool
}

func newRelayObserverFixture(t *testing.T) (*Mempool, *ChainState, *PendingOutpointOwner) {
	t.Helper()
	chainState := NewChainState()
	mempool, err := NewMempool(chainState, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("NewMempool: %v", err)
	}
	return mempool, chainState, mempool.PendingOutpointOwner()
}

// setRelaySource changes the source tuple under the owner's own mutex.
func setRelaySource(owner *PendingOutpointOwner, tip PendingOutpointTip, generation uint64) {
	owner.mu.Lock()
	owner.stableTip, owner.generation = tip, generation
	owner.mu.Unlock()
}

func observeRelayAsync(m *Mempool) <-chan relayObservation {
	done := make(chan relayObservation, 1)
	go func() {
		ctx, ok := m.AdmissionContextForRelay()
		done <- relayObservation{ctx: ctx, ok: ok}
	}()
	return done
}

func awaitRelayObservation(t *testing.T, done <-chan relayObservation, name string) relayObservation {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(relayObserverLiveness):
		t.Fatalf("%s: external observer did not return", name)
		return relayObservation{}
	}
}

func requireRelayObservation(t *testing.T, got relayObservation, want PendingOutpointAdmissionContext, wantOK bool, name string) {
	t.Helper()
	if got.ok != wantOK || got.ctx != want {
		t.Fatalf("%s: observation=(%+v,%v), want (%+v,%v)", name, got.ctx, got.ok, want, wantOK)
	}
}

func requireRelayUnavailableWhileOwnerHeld(t *testing.T, m *Mempool, owner *PendingOutpointOwner, name string) {
	t.Helper()
	owner.mu.Lock()
	got := awaitRelayObservation(t, observeRelayAsync(m), name)
	owner.mu.Unlock()
	requireRelayObservation(t, got, PendingOutpointAdmissionContext{}, false, name)
}

// startRelayWriter begins a real exclusive acquisition of the admission guard.
// acquired closes once the writer holds it; closing release lets it unlock.
func startRelayWriter(guard *admissionMutex) (acquired <-chan struct{}, release chan<- struct{}, done <-chan struct{}) {
	acquiredCh, releaseCh, doneCh := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		guard.Lock()
		close(acquiredCh)
		<-releaseCh
		guard.Unlock()
		close(doneCh)
	}()
	return acquiredCh, releaseCh, doneCh
}

// awaitPendingRelayWriter observes the writer's registration as native
// TryRLock refusal, releasing every successful probe.
func awaitPendingRelayWriter(t *testing.T, guard *admissionMutex) {
	t.Helper()
	deadline := time.Now().Add(relayObserverLiveness)
	for guard.TryRLock() {
		guard.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("writer registration was never observed through TryRLock refusal")
		}
		runtime.Gosched()
	}
}

// awaitOwnerMutexWaiter observes, from goroutine stacks, a reader parked on
// owner.mu inside PendingOutpointOwner.AdmissionContext below a frame matching
// caller. It proves the read really waits on the contended source mutex; no
// production hook is involved. A reader that returns instead of waiting is
// judged on the value it returned: it cannot carry want, which is installed
// only after this wait.
func awaitOwnerMutexWaiter(t *testing.T, caller string, result <-chan relayObservation, want PendingOutpointAdmissionContext, name string) {
	t.Helper()
	deadline, stack := time.Now().Add(relayObserverLiveness), make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		select {
		case got := <-result:
			requireRelayObservation(t, got, want, true, name+" (returned without waiting on owner.mu)")
			t.Fatalf("%s: returned without waiting on owner.mu", name)
		default:
		}
		n := runtime.Stack(stack, true)
		if n == len(stack) {
			stack = make([]byte, 2*len(stack))
			continue
		}
		for _, g := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(g, "SemacquireMutex") && strings.Contains(g, "(*PendingOutpointOwner).AdmissionContext(") && strings.Contains(g, caller) {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("%s: no %q reader parked on owner.mu in AdmissionContext", name, caller)
}

func awaitRelaySignal(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(relayObserverLiveness):
		t.Fatalf("timed out waiting for %s", name)
	}
}

// requireRelayGuardReleased proves no read grant leaked: a writer acquires.
func requireRelayGuardReleased(t *testing.T, guard *admissionMutex, name string) {
	t.Helper()
	if !guard.TryLock() {
		t.Fatalf("%s: the admission read grant leaked past return", name)
	}
	guard.Unlock()
}

// TestRelayAdmissionContextForRelay pins the external relay-cache observer
// against real native locks: A1-A4 and A6-A9, R1-R3 and H1-H3. A5 lives in
// TestSyncEnginePostCommitFaultKeepsAdmissionClosedAfterLatch.
func TestRelayAdmissionContextForRelay(t *testing.T) {
	hashA, hashB := [32]byte{0xA1}, [32]byte{0xB2}
	zero := PendingOutpointAdmissionContext{}

	t.Run("A1_complete_source_follows_each_component", func(t *testing.T) {
		m, _, owner := newRelayObserverFixture(t)
		for _, step := range []struct {
			name string
			ctx  PendingOutpointAdmissionContext
		}{
			{"tip A", PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 5, Hash: hashA}, Generation: 3}},
			{"height only", PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 6, Hash: hashA}, Generation: 3}},
			{"hash only", PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 6, Hash: hashB}, Generation: 3}},
			{"generation only", PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 6, Hash: hashB}, Generation: 4}},
			{"A->B->A fresh generation", PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 5, Hash: hashA}, Generation: 5}},
			{"zero height and hash with tip", PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true}, Generation: 6}},
		} {
			setRelaySource(owner, step.ctx.StableTip, step.ctx.Generation)
			ctx, ok := m.AdmissionContextForRelay()
			requireRelayObservation(t, relayObservation{ctx, ok}, step.ctx, true, step.name)
			if internal, _ := owner.AdmissionContext(); internal != ctx {
				t.Fatalf("%s: external=%+v, internal source=%+v", step.name, ctx, internal)
			}
		}
	})

	t.Run("A2_H3_missing_source_or_component", func(t *testing.T) {
		var nilPool *Mempool
		ctx, ok := nilPool.AdmissionContextForRelay()
		requireRelayObservation(t, relayObservation{ctx, ok}, zero, false, "nil receiver")

		// HasTip=false is absent even though the source is stable.
		m, chainState, owner := newRelayObserverFixture(t)
		ctx, ok = m.AdmissionContextForRelay()
		requireRelayObservation(t, relayObservation{ctx, ok}, zero, false, "HasTip=false")

		// With owner.mu held, every missing-binding row must still complete:
		// it reads no owner state.
		setRelaySource(owner, PendingOutpointTip{HasTip: true, Height: 1, Hash: hashA}, 1)
		requireRelayUnavailableWhileOwnerHeld(t, &Mempool{}, owner, "zero Mempool")
		noOwner := &Mempool{chainState: chainState, pendingOutpoints: owner, relaySource: relayAdmissionSource{chainState: chainState}}
		requireRelayUnavailableWhileOwnerHeld(t, noOwner, owner, "absent bound owner")
		noChain := &Mempool{chainState: chainState, pendingOutpoints: owner, relaySource: relayAdmissionSource{owner: owner}}
		requireRelayUnavailableWhileOwnerHeld(t, noChain, owner, "absent bound ChainState")

		// A bare pool's legacy lazy owner, created concurrently under m.mu, is
		// never observed: the observer reads only the immutable binding, so the
		// race detector sees no access to pendingOutpoints.
		bare := &Mempool{chainState: chainState}
		lazy := make(chan *PendingOutpointOwner, 1)
		go func() {
			bare.mu.Lock()
			lazy <- bare.pendingOutpointOwnerLocked()
			bare.mu.Unlock()
		}()
		requireRelayObservation(t, awaitRelayObservation(t, observeRelayAsync(bare), "bare racing lazy"), zero, false, "bare racing lazy")
		lazyOwner := <-lazy
		setRelaySource(lazyOwner, PendingOutpointTip{HasTip: true, Height: 2, Hash: hashB}, 2)
		ctx, ok = bare.AdmissionContextForRelay()
		requireRelayObservation(t, relayObservation{ctx, ok}, zero, false, "bare after lazy owner")
		if bare.relaySource != (relayAdmissionSource{}) {
			t.Fatalf("bare pool acquired an external binding: %+v", bare.relaySource)
		}
		empty := &Mempool{chainState: chainState}
		empty.AdmissionContextForRelay()
		if empty.pendingOutpoints != nil {
			t.Fatal("the observer lazily installed an owner")
		}
	})

	t.Run("A3_R1_active_writer_refuses_without_waiting", func(t *testing.T) {
		m, chainState, owner := newRelayObserverFixture(t)
		setRelaySource(owner, PendingOutpointTip{HasTip: true, Height: 9, Hash: hashA}, 2)
		guard := &chainState.admissionMu
		guard.Lock()
		requireRelayUnavailableWhileOwnerHeld(t, m, owner, "active writer")
		guard.Unlock()
	})

	t.Run("A4_R1_H2_pending_writer_refuses_without_waiting", func(t *testing.T) {
		m, chainState, owner := newRelayObserverFixture(t)
		setRelaySource(owner, PendingOutpointTip{HasTip: true, Height: 9, Hash: hashA}, 2)
		guard := &chainState.admissionMu
		guard.RLock() // the initial reader keeps the writer pending
		acquired, release, done := startRelayWriter(guard)
		awaitPendingRelayWriter(t, guard)
		requireRelayUnavailableWhileOwnerHeld(t, m, owner, "pending writer")
		select {
		case <-acquired:
			t.Fatal("writer acquired while the initial reader still held the guard")
		default:
		}
		guard.RUnlock()
		awaitRelaySignal(t, acquired, "pending writer acquisition")
		close(release)
		awaitRelaySignal(t, done, "writer release")
	})

	t.Run("A6_H1_source_contention_returns_the_tuple_read", func(t *testing.T) {
		m, chainState, owner := newRelayObserverFixture(t)
		want := PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 11, Hash: hashB}, Generation: 7}

		// Public path, no writer: contention on owner.mu is waited out, never
		// reported as unavailability.
		owner.mu.Lock()
		done := observeRelayAsync(m)
		awaitOwnerMutexWaiter(t, "(*Mempool).AdmissionContextForRelay(", done, want, "contended public read")
		owner.stableTip, owner.generation = want.StableTip, want.Generation
		owner.mu.Unlock()
		requireRelayObservation(t, awaitRelayObservation(t, done, "contended public read"), want, true, "contended public read")

		// Composition under an already-granted read: the bound source's own
		// read waits on owner.mu while a writer registers afterwards; that
		// registration does not invalidate the tuple actually read, and only
		// releasing the granted read lets the writer proceed.
		guard := &chainState.admissionMu
		guard.RLock()
		owner.mu.Lock()
		read := make(chan relayObservation, 1)
		go func() {
			ctx, ok := m.relaySource.owner.AdmissionContext()
			read <- relayObservation{ctx: ctx, ok: ok}
		}()
		awaitOwnerMutexWaiter(t, "relay_admission_context_test.go", read, PendingOutpointAdmissionContext{StableTip: want.StableTip, Generation: 8}, "late writer")
		acquired, release, writerDone := startRelayWriter(guard)
		awaitPendingRelayWriter(t, guard)
		want.Generation = 8
		owner.generation = want.Generation
		owner.mu.Unlock()
		requireRelayObservation(t, awaitRelayObservation(t, read, "granted source read"), want, true, "late writer")
		select {
		case <-acquired:
			t.Fatal("writer acquired before the granted read was released")
		default:
		}
		guard.RUnlock()
		awaitRelaySignal(t, acquired, "late writer acquisition")
		close(release)
		awaitRelaySignal(t, writerDone, "late writer release")
	})

	t.Run("A7_H2_exhausted_generation_is_unavailable_and_releases", func(t *testing.T) {
		m, chainState, owner := newRelayObserverFixture(t)
		tip := PendingOutpointTip{HasTip: true, Height: 3, Hash: hashA}
		setRelaySource(owner, tip, math.MaxUint64-1)
		ctx, ok := m.AdmissionContextForRelay()
		requireRelayObservation(t, relayObservation{ctx, ok}, PendingOutpointAdmissionContext{StableTip: tip, Generation: math.MaxUint64 - 1}, true, "last valid generation")

		setRelaySource(owner, tip, math.MaxUint64)
		ctx, ok = m.AdmissionContextForRelay()
		requireRelayObservation(t, relayObservation{ctx, ok}, zero, false, "exhausted generation")
		requireRelayGuardReleased(t, &chainState.admissionMu, "exhausted generation")
		if !owner.mu.TryLock() {
			t.Fatal("exhausted path leaked owner.mu")
		}
		owner.mu.Unlock()
	})

	t.Run("A8_R3_releases_and_takes_no_domain_lock", func(t *testing.T) {
		m, chainState, owner := newRelayObserverFixture(t)
		guard := &chainState.admissionMu
		want := PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 4, Hash: hashB}, Generation: 2}

		for _, path := range []struct {
			name   string
			ctx    PendingOutpointAdmissionContext
			wantOK bool
		}{
			{"source success", want, true},
			{"source false", PendingOutpointAdmissionContext{StableTip: want.StableTip, Generation: math.MaxUint64}, false},
		} {
			setRelaySource(owner, path.ctx.StableTip, path.ctx.Generation)
			ctx, ok := m.AdmissionContextForRelay()
			wantCtx := zero
			if path.wantOK {
				wantCtx = path.ctx
			}
			requireRelayObservation(t, relayObservation{ctx, ok}, wantCtx, path.wantOK, path.name)
			requireRelayGuardReleased(t, guard, path.name)
		}

		// Holding Mempool.mu and ChainState.mu does not block the observer.
		setRelaySource(owner, want.StableTip, want.Generation)
		m.mu.Lock()
		chainState.mu.Lock()
		got := awaitRelayObservation(t, observeRelayAsync(m), "domain locks held")
		chainState.mu.Unlock()
		m.mu.Unlock()
		requireRelayObservation(t, got, want, true, "domain locks held")
	})

	t.Run("A9_constructor_binding_is_pointer_identical", func(t *testing.T) {
		m, chainState, owner := newRelayObserverFixture(t)
		if m.relaySource.chainState != chainState || m.relaySource.chainState != m.chainState {
			t.Fatal("external binding references a different ChainState")
		}
		if m.relaySource.owner == nil || m.relaySource.owner != owner || m.relaySource.owner != m.pendingOutpoints {
			t.Fatal("external binding references a different PendingOutpointOwner")
		}
		want := PendingOutpointAdmissionContext{StableTip: PendingOutpointTip{HasTip: true, Height: 21, Hash: hashA}, Generation: 9}
		setRelaySource(m.PendingOutpointOwner(), want.StableTip, want.Generation)
		ctx, ok := m.AdmissionContextForRelay()
		requireRelayObservation(t, relayObservation{ctx, ok}, want, true, "pool owner tuple")

		other, err := NewMempool(chainState, nil, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("NewMempool: %v", err)
		}
		if other.relaySource.owner == owner {
			t.Fatal("a second pool shares the first pool's owner")
		}
		ctx, ok = other.AdmissionContextForRelay()
		requireRelayObservation(t, relayObservation{ctx, ok}, zero, false, "second pool's own source")
	})
}
