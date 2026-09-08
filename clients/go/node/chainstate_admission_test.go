package node

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestAdmissionFenceTerminalWake(t *testing.T) {
	join := func(ch <-chan bool, label string) bool {
		t.Helper()
		select {
		case got := <-ch:
			return got
		case <-time.After(time.Second):
			t.Fatalf("%s did not return", label)
			return false
		}
	}

	var immediate admissionMutex
	if !immediate.RLockUnlessTerminal() {
		t.Fatal("zero-value immediate reader was refused")
	}
	if immediate.TryLock() {
		immediate.Unlock()
		t.Fatal("held read lock did not exclude a writer")
	}
	immediate.RUnlock()

	var ordinary admissionMutex
	ordinary.Lock()
	ordinaryResult := make(chan bool, 1)
	ordinaryRelease := make(chan struct{})
	ordinaryDone := make(chan struct{})
	ordinaryLocked, ordinaryReleased := true, false
	cleanupOrdinary := func() bool {
		if ordinaryLocked {
			ordinary.Unlock()
			ordinaryLocked = false
		}
		if !ordinaryReleased {
			close(ordinaryRelease)
			ordinaryReleased = true
		}
		ordinary.notifyTerminal()
		select {
		case <-ordinaryDone:
			return true
		case <-time.After(time.Second):
			return false
		}
	}
	defer cleanupOrdinary()
	go func() {
		defer close(ordinaryDone)
		acquired := ordinary.RLockUnlessTerminal()
		ordinaryResult <- acquired
		<-ordinaryRelease
		if acquired {
			ordinary.RUnlock()
		}
	}()
	awaitCanonicalMOAdmissionRLock(t, "TestAdmissionFenceTerminalWake", 1)
	ordinary.Unlock()
	ordinaryLocked = false
	if !join(ordinaryResult, "ordinary queued reader") {
		t.Fatal("ordinary contention refused a queued reader")
	}
	if ordinary.TryLock() {
		ordinary.Unlock()
		t.Fatal("ordinary contention did not resume with a held read lock")
	}
	if !cleanupOrdinary() {
		t.Fatal("ordinary queued reader did not finish")
	}

	var terminal admissionMutex
	terminal.Lock()
	const readers = 4
	results := make(chan bool, readers)
	for i := 0; i < readers; i++ {
		go func() { results <- terminal.RLockUnlessTerminal() }()
	}
	awaitCanonicalMOAdmissionRLock(t, "TestAdmissionFenceTerminalWake", readers)
	terminal.notifyTerminal()
	for i := 0; i < readers; i++ {
		if join(results, "terminal queued reader") {
			t.Fatal("terminal queued reader acquired the fence")
		}
	}
	terminal.notifyTerminal()
	fresh := make(chan bool, 1)
	go func() { fresh <- terminal.RLockUnlessTerminal() }()
	if join(fresh, "fresh terminal reader") {
		terminal.RUnlock()
		t.Fatal("fresh reader acquired after repeated terminal notification")
	}
	if terminal.TryLock() {
		terminal.Unlock()
		t.Fatal("terminal notification released the writer")
	}
}

func terminalizeAdmissionFixture(t *testing.T, f *canonicalMOFixture, truth canonicalCommitTruth) {
	t.Helper()
	transition, err := f.engine.beginCanonicalTransition(&diagnosticBatch{})
	mustCanonicalMO(t, "beginCanonicalTransition", err)
	plan := &canonicalTransitionPlan{final: cloneChainState(f.engine.chainState)}
	transition.publishCanonicalTransition(plan, canonicalFenceImage{}, truth, &storagePersistenceFault{cause: errors.New("terminal admission test")}, "")
}

func TestTerminalAdmissionReadersReturnUnavailable(t *testing.T) {
	const unavailable = "pending-outpoint owner admission context unavailable"
	f := newCanonicalMOFixture(t, 4, MempoolConfig{})
	relay, owner := f.engine.DARelayState(), f.mp.PendingOutpointOwner()
	daID := daRelayTestID(0xd1)
	retained := f.ownerReadyCommitTx(t, f.ops[1], daID, 2, 10)
	if result, err := relay.AdmitDA(retained, LocalDAProvenance()); err != nil || result.Disposition != DAAdmissionRetained {
		t.Fatalf("seed retained result=%+v err=%v", result, err)
	}
	plans, diagnostic := relay.PlanPrefetch(daID, []string{"terminal-peer"}, time.Unix(1, 0))
	if len(plans) != 1 || diagnostic != "" {
		t.Fatalf("seed prefetch plans=%+v diagnostic=%q", plans, diagnostic)
	}
	standard := f.raw(t, f.ops[0], 11, false)
	da := f.ownerReadyCommitTx(t, f.ops[2], daRelayTestID(0xd2), 2, 12)

	terminalizeAdmissionFixture(t, f, canonicalTruthOld)
	chainBefore := f.engine.chainState.view()
	poolBefore := fingerprintPool(f.mp)
	relayBefore := daRelayStateSnapshot(relay)
	ownerBefore := owner.snapshot()
	countsBefore := f.mp.AdmissionCounts()

	f.engine.chainState.mu.Lock()
	f.mp.mu.Lock()
	relay.mu.Lock()
	owner.mu.Lock()
	locked := true
	unlockImages := func() {
		if !locked {
			return
		}
		owner.mu.Unlock()
		relay.mu.Unlock()
		f.mp.mu.Unlock()
		f.engine.chainState.mu.Unlock()
		locked = false
	}
	defer unlockImages()
	run := func(name string, call func() error) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			return err
		case <-time.After(time.Second):
			unlockImages()
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			t.Fatalf("%s reached a terminal image lock", name)
			return nil
		}
	}
	requireUnavailable := func(name string, err error) {
		t.Helper()
		var typed *TxAdmitError
		if !errors.As(err, &typed) || typed.Kind != TxAdmitUnavailable || err.Error() != unavailable {
			t.Fatalf("%s=%T %v, want exact unavailable", name, err, err)
		}
		if (name == "AdmitDA" || name == "AddTx") && relayDispositionOf(err) != RelayAdmissionUnavailable {
			t.Fatalf("%s disposition=%s, want UNAVAILABLE", name, relayDispositionOf(err))
		}
	}

	rows := []struct {
		name string
		call func() error
	}{
		{"AdmitDA", func() error {
			result, err := relay.AdmitDA(da, LocalDAProvenance())
			if result != (DAAdmissionResult{}) {
				return fmt.Errorf("result=%+v", result)
			}
			return err
		}},
		{"BeginDAAdmission", func() error {
			admission, err := f.mp.BeginDAAdmission(da)
			if admission != nil {
				return errors.New("non-nil admission")
			}
			return err
		}},
		{"BeginDARemoval", func() error {
			removal, err := f.mp.BeginDARemoval()
			if removal != nil {
				return errors.New("non-nil removal")
			}
			return err
		}},
		{"AddTx", func() error { return f.mp.AddTx(standard) }},
		{"RelayMetadata", func() error {
			metadata, err := f.mp.RelayMetadata(standard)
			if metadata != (RelayTxMetadata{}) {
				return fmt.Errorf("metadata=%+v", metadata)
			}
			return err
		}},
		{"withLockedParsedBlock", func() error { return f.mp.EvictConfirmedParsed(&consensus.ParsedBlock{}) }},
		{"PlanPrefetch", func() error {
			got, diagnostic := relay.PlanPrefetch(daID, []string{"other-peer"}, time.Unix(2, 0))
			if got != nil || diagnostic != unavailable {
				return fmt.Errorf("plans=%+v diagnostic=%q", got, diagnostic)
			}
			return nil
		}},
		{"ReleasePrefetchPlan", func() error { relay.ReleasePrefetchPlan(plans[0]); return nil }},
		{"commitOwnerReadyRemoval", func() error { return relay.AdvanceOrphanTTL() }},
	}
	for _, row := range rows {
		err := run(row.name, row.call)
		if row.name != "PlanPrefetch" && row.name != "ReleasePrefetchPlan" {
			requireUnavailable(row.name, err)
		} else if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
	}
	unlockImages()

	if got := f.engine.chainState.view(); got != chainBefore {
		t.Fatalf("chain image changed: got=%+v want=%+v", got, chainBefore)
	}
	poolAfter := fingerprintPool(f.mp)
	wantPool := poolBefore
	wantPool.admission.Unavailable++
	wantPool.ownerInTransition = true
	if poolAfter != wantPool {
		t.Fatalf("pool image=%+v want=%+v", poolAfter, wantPool)
	}
	requireDARelayStateUnchanged(t, relay, relayBefore)
	if got := owner.snapshot(); got.stableTip != ownerBefore.stableTip || got.tokenHighWater != ownerBefore.tokenHighWater || got.generationHighWater != ownerBefore.generationHighWater || !slices.EqualFunc(got.claims, ownerBefore.claims, func(a, b pendingOutpointClaim) bool {
		return a.token == b.token && a.domain == b.domain && a.txid == b.txid && a.generation == b.generation && a.finalized == b.finalized && slices.Equal(a.inputs, b.inputs)
	}) {
		t.Fatalf("owner image changed: got=%+v want=%+v", got, ownerBefore)
	}
	if got := f.mp.AdmissionCounts(); got != (MempoolAdmissionCounts{Accepted: countsBefore.Accepted, Conflict: countsBefore.Conflict, Rejected: countsBefore.Rejected, Unavailable: countsBefore.Unavailable + 1}) {
		t.Fatalf("standard terminal counts=%+v, want one unavailable added", got)
	}
	if f.engine.chainState.admissionMu.TryLock() {
		f.engine.chainState.admissionMu.Unlock()
		t.Fatal("terminal writer was released")
	}

	for _, row := range []struct {
		name string
		run  func(*canonicalMOFixture)
	}{
		{"pre-fence", func(f *canonicalMOFixture) {
			cause := &canonicalStoreIntegrityError{cause: errors.New("corrupt canonical artifact")}
			_ = f.engine.latchPreFenceCanonicalCorruption(cause, &diagnosticBatch{})
		}},
		{"precommit", func(f *canonicalMOFixture) {
			transition, err := f.engine.beginCanonicalTransition(&diagnosticBatch{})
			mustCanonicalMO(t, "beginCanonicalTransition", err)
			_ = transition.end(&canonicalMOTerminalError{detail: "test invariant"})
		}},
		{"postcommit OLD", func(f *canonicalMOFixture) { terminalizeAdmissionFixture(t, f, canonicalTruthOld) }},
		{"postcommit NEW", func(f *canonicalMOFixture) { terminalizeAdmissionFixture(t, f, canonicalTruthNew) }},
		{"postcommit UNKNOWN", func(f *canonicalMOFixture) { terminalizeAdmissionFixture(t, f, canonicalTruthUnknown) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			candidate := newCanonicalMOFixture(t, 1, MempoolConfig{})
			row.run(candidate)
			fresh := make(chan bool, 1)
			go func() { fresh <- candidate.engine.chainState.admissionMu.RLockUnlessTerminal() }()
			select {
			case acquired := <-fresh:
				if !candidate.engine.persistenceFaulted() || acquired {
					t.Fatal("terminal producer did not refuse a fresh reader")
				}
			case <-time.After(time.Second):
				t.Fatal("fresh terminal reader did not return")
			}
			if candidate.engine.chainState.admissionMu.TryLock() {
				candidate.engine.chainState.admissionMu.Unlock()
				t.Fatal("terminal producer released the writer")
			}
		})
	}
}
