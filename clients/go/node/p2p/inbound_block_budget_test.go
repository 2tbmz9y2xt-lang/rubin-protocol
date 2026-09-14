package p2p

import (
	"errors"
	"math"
	"runtime"
	"sync"
	"testing"
)

func TestInboundBlockBudget(t *testing.T) {
	for _, row := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"config_default", func(t *testing.T) { requireBudgetLimit(t, 0, 1073741824) }},
		{"config_min", func(t *testing.T) { requireBudgetLimit(t, 1073741824, 1073741824) }},
		{"config_max", func(t *testing.T) { requireBudgetLimit(t, 8589934592, 8589934592) }},
		{"config_below_min", func(t *testing.T) { requireConfigRejected(t, 1, 1073741823) }},
		{"config_above_max", func(t *testing.T) { requireConfigRejected(t, 8589934593, math.MaxUint64) }},
		{"config_table", func(t *testing.T) {
			for _, cfg := range []struct{ configured, limit uint64 }{
				{0, 1073741824}, {1073741824, 1073741824}, {2147483648, 2147483648},
				{4294967296, 4294967296}, {8589934592, 8589934592},
			} {
				requireBudgetLimit(t, cfg.configured, cfg.limit)
			}
		}},
		{"config_no_proportional_alloc", func(t *testing.T) {
			for _, configured := range []uint64{1073741824, 8589934592} {
				got := allocBytesPerOp(t, func() { _, _ = newInboundBlockBudget(configured) })
				requireTrue(t, got <= 1024, "newInboundBlockBudget(%d) allocated %d bytes per call, want <= 1024", configured, got)
			}
		}},
		{"unsupported_command", func(t *testing.T) {
			for _, command := range []string{"", "blocktxn", "tx", "getdata", "BLOCK", "block "} {
				charge, err := inboundBlockCharge(command, 1000)
				requireTrue(t, charge == 0 && err != nil && err.Error() == "unsupported inbound block budget command", "inboundBlockCharge(%q, 1000) = (%d, %v)", command, charge, err)
				requireOrdinaryError(t, err)
			}
		}},
		{"charge_not_capped", func(t *testing.T) {
			charge, err := inboundBlockCharge("block", 72000001)
			requireTrue(t, charge == 432000006 && err == nil, "inboundBlockCharge(block, 72000001) = (%d, %v), want (432000006, nil)", charge, err)
		}},
		{"overflow", func(t *testing.T) {
			charge, err := inboundBlockCharge("block", 3074457345618258603)
			requireTrue(t, charge == 0, "overflowing charge returned %d", charge)
			_ = assertResourceTuple(t, err, "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_overflow)", "inbound_budget_overflow", false, false)
			fits, err := inboundBlockCharge("block", 3074457345618258602)
			requireTrue(t, fits == 18446744073709551612 && err == nil, "largest fitting block charge = (%d, %v)", fits, err)
		}},
		{"exact_fit", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			mustReserve(t, b, 1073741824)
			requireUsed(t, b, 1073741824)
		}},
		{"zero_charge", func(t *testing.T) {
			b := newTestBudget(t, 0)
			lease := mustReserve(t, b, 0)
			requireUsed(t, b, 0)
			lease.Release()
			requireUsed(t, b, 0)
		}},
		{"refusal_no_mutation", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			holder := mustReserve(t, b, 1000)
			gen := generationOf(b)
			before := runtime.NumGoroutine()
			for i := 0; i < 1000; i++ {
				lease, err := b.TryReserveOrSubscribe(1073740825)
				requireTrue(t, lease == nil && requireCapacityRefusal(t, err).Notification() == gen, "refusal returned lease=%v or a foreign generation", lease)
			}
			// ponytail: a margin for runtime-owned goroutines; one waiter per refusal would add 1000.
			spawned := runtime.NumGoroutine() - before
			requireTrue(t, spawned <= 10, "1000 refusals left %d new goroutines", spawned)
			requireUsed(t, b, 1000)
			requireTrue(t, holder.active && holder.charge == 1000, "refusal disturbed the existing holder: active=%v charge=%d", holder.active, holder.charge)
			holder.Release()
			mustReserve(t, b, 1073741824)
		}},
		{"capacity_tuple", func(t *testing.T) {
			_, err := preheldBudget(t).TryReserveOrSubscribe(1)
			_ = assertResourceTuple(t, err, "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_capacity)", "inbound_budget_capacity", true, false)
		}},
		{"overflow_tuple", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			mustReserve(t, b, 1)
			_, err := b.TryReserveOrSubscribe(math.MaxUint64)
			_ = assertResourceTuple(t, err, "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_overflow)", "inbound_budget_overflow", false, false)
		}},
		{"reserve_overflow", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			holder := mustReserve(t, b, 4096)
			lease, err := b.TryReserveOrSubscribe(math.MaxUint64)
			requireTrue(t, lease == nil, "overflowing reservation handed back a lease")
			_ = assertResourceTuple(t, err, "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_overflow)", "inbound_budget_overflow", false, false)
			requireUsed(t, b, 4096)
			requireTrue(t, holder.active && holder.charge == 4096, "overflow disturbed the existing holder")
		}},
		{"invalid_lease_precedes_arithmetic", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			other := newTestBudget(t, 1073741824)
			mustReserve(t, b, 4096)
			foreign := mustReserve(t, other, 512)
			released := mustReserve(t, b, 256)
			released.Release()
			for _, invalid := range []struct {
				name  string
				lease *inboundBlockLease
			}{{"nil", nil}, {"foreign", foreign}, {"released", released}} {
				err := replaceWithoutPanic(t, b, invalid.lease, math.MaxUint64)
				requireInvalidLease(t, err, invalid.name)
				requireUsed(t, b, 4096)
				requireUsed(t, other, 512)
			}
			requireTrue(t, foreign.charge == 512 && foreign.active, "foreign lease mutated: charge=%d", foreign.charge)
		}},
		{"foreign_lease", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			other := newTestBudget(t, 1073741824)
			mustReserve(t, b, 4096)
			foreign := mustReserve(t, other, 512)
			requireInvalidLease(t, b.ReplaceOrSubscribe(foreign, 1), "foreign")
			requireUsed(t, b, 4096)
			requireUsed(t, other, 512)
			requireTrue(t, foreign.charge == 512 && foreign.owner == other, "foreign lease mutated: charge=%d", foreign.charge)
		}},
		{"released_lease", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			mustReserve(t, b, 4096)
			released := mustReserve(t, b, 512)
			released.Release()
			requireInvalidLease(t, b.ReplaceOrSubscribe(released, 1), "released")
			requireUsed(t, b, 4096)
		}},
		{"replace_not_additive", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			lease := mustReserve(t, b, 1000)
			requireTrue(t, b.ReplaceOrSubscribe(lease, 2000) == nil, "replacement refused")
			requireUsed(t, b, 2000)
			requireTrue(t, lease.charge == 2000 && lease.active, "replacement did not re-price the same lease: charge=%d active=%v", lease.charge, lease.active)
		}},
		{"replace_reconstruction", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			lease := mustReserve(t, b, 216000000)
			requireTrue(t, b.ReplaceOrSubscribe(lease, 864000000) == nil, "reconstruction replacement refused")
			requireUsed(t, b, 864000000)
			requireTrue(t, lease.charge == 864000000, "lease charge = %d, want 864000000", lease.charge)
		}},
		{"replace_overflow", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			mustReserve(t, b, 4096)
			lease := mustReserve(t, b, 1000)
			err := b.ReplaceOrSubscribe(lease, math.MaxUint64)
			_ = assertResourceTuple(t, err, "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_overflow)", "inbound_budget_overflow", false, false)
			requireUsed(t, b, 5096)
			requireTrue(t, lease.charge == 1000 && lease.active, "overflowing replacement disturbed the lease: charge=%d active=%v", lease.charge, lease.active)
		}},
		{"failed_replace_retains", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			mustReserve(t, b, 4096)
			lease := mustReserve(t, b, 1000)
			gen := generationOf(b)
			err := b.ReplaceOrSubscribe(lease, 1073741824)
			refusal := assertResourceTuple(t, err, "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_capacity)", "inbound_budget_capacity", true, false)
			requireTrue(t, refusal.Notification() == gen, "refused replacement did not carry the current generation")
			requireUsed(t, b, 5096)
			requireTrue(t, lease.charge == 1000 && lease.active, "refused replacement released the old lease: charge=%d active=%v", lease.charge, lease.active)
			requireTrue(t, !isClosed(gen), "refused replacement published capacity")
		}},
		{"downward_notifies", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			lease := mustReserve(t, b, 4096)
			gen := generationOf(b)
			err := b.ReplaceOrSubscribe(lease, 1024)
			requireTrue(t, err == nil, "downward replacement refused: %v", err)
			fresh := generationOf(b)
			requireTrue(t, isClosed(gen) && fresh != gen && !isClosed(fresh), "downward replacement did not publish the freed capacity under a fresh generation")
			requireUsed(t, b, 1024)
		}},
		{"equal_does_not_notify", func(t *testing.T) { requireSilentReplace(t, 4096, 4096) }},
		{"growth_does_not_notify", func(t *testing.T) { requireSilentReplace(t, 4096, 8192) }},
		{"release_before_wait", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			holder := mustReserve(t, b, 1073741824)
			_, err := b.TryReserveOrSubscribe(1)
			notification := requireCapacityRefusal(t, err).Notification()
			requireTrue(t, notification != nil && !isClosed(notification), "refusal handed back a missing or already closed generation")
			holder.Release()
			requireTrue(t, isClosed(notification), "a release before the consumer started waiting was lost")
			<-notification
			requireUsed(t, b, 0)
		}},
		{"zero_release", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			mustReserve(t, b, 4096)
			zero := mustReserve(t, b, 0)
			gen := generationOf(b)
			zero.Release()
			requireTrue(t, !isClosed(gen) && generationOf(b) == gen, "zero-charge release published capacity")
			requireUsed(t, b, 4096)
		}},
		{"double_release", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			lease := mustReserve(t, b, 4096)
			lease.Release()
			requireUsed(t, b, 0)
			gen := generationOf(b)
			lease.Release()
			requireUsed(t, b, 0)
			requireTrue(t, !isClosed(gen) && generationOf(b) == gen, "second release published capacity")
		}},
		{"nil_release", func(t *testing.T) { releaseWithoutPanic(t, nil) }},
		{"stale_alias", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			other := mustReserve(t, b, 4096)
			lease := mustReserve(t, b, 1000)
			alias := lease
			lease.Release()
			requireUsed(t, b, 4096)
			releaseWithoutPanic(t, alias)
			requireUsed(t, b, 4096)
			requireInvalidLease(t, replaceWithoutPanic(t, b, alias, 2000), "stale alias")
			requireUsed(t, b, 4096)
			requireTrue(t, other.active && other.charge == 4096, "stale alias disturbed another reservation")
		}},
		{"two_holders", func(t *testing.T) {
			for _, order := range [][2]int{{0, 1}, {1, 0}} {
				b := newTestBudget(t, 1073741824)
				charges := [2]uint64{4096, 1000}
				leases := [2]*inboundBlockLease{mustReserve(t, b, charges[0]), mustReserve(t, b, charges[1])}
				requireUsed(t, b, 5096)
				leases[order[0]].Release()
				requireUsed(t, b, charges[order[1]])
				leases[order[1]].Release()
				requireUsed(t, b, 0)
			}
		}},
		{"concurrent_holders", func(t *testing.T) {
			const charge = 1 << 20
			for _, holders := range []int{1, 2, 4, 8} {
				b := newTestBudget(t, 1073741824)
				var reserved, release, done sync.WaitGroup
				reserved.Add(holders)
				done.Add(holders)
				release.Add(1)
				for i := 0; i < holders; i++ {
					go func() {
						lease, _ := b.TryReserveOrSubscribe(charge)
						reserved.Done()
						release.Wait()
						lease.Release()
						done.Done()
					}()
				}
				reserved.Wait()
				requireUsed(t, b, uint64(holders)*charge)
				release.Done()
				done.Wait()
				requireUsed(t, b, 0)
			}
		}},
		{"replace_release_race", func(t *testing.T) {
			for i := 0; i < 200; i++ {
				b := newTestBudget(t, 1073741824)
				lease := mustReserve(t, b, 4096)
				var finished sync.WaitGroup
				finished.Add(1)
				start := make(chan struct{})
				var replaceErr error
				go func() { defer finished.Done(); <-start; replaceErr = b.ReplaceOrSubscribe(lease, 1024) }()
				close(start)
				lease.Release()
				finished.Wait()
				requireTrue(t, replaceErr == nil || replaceErr.Error() == "invalid inbound block lease", "replace/release race produced %v", replaceErr)
				requireUsed(t, b, 0)
			}
		}},
	} {
		t.Run(row.name, row.run)
	}
}

// requireTrue fails the calling test line when ok is false.
func requireTrue(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func newTestBudget(t *testing.T, configured uint64) *inboundBlockBudget {
	t.Helper()
	b, err := newInboundBlockBudget(configured)
	requireTrue(t, b != nil && err == nil, "newInboundBlockBudget(%d) = (%v, %v)", configured, b, err)
	return b
}

func requireBudgetLimit(t *testing.T, configured, want uint64) {
	t.Helper()
	b := newTestBudget(t, configured)
	requireTrue(t, b.limit == want, "newInboundBlockBudget(%d) limit = %d, want %d", configured, b.limit, want)
	requireUsed(t, b, 0)
}

func requireConfigRejected(t *testing.T, configured ...uint64) {
	t.Helper()
	for _, value := range configured {
		b, err := newInboundBlockBudget(value)
		requireTrue(t, b == nil && err != nil && err.Error() == "inbound block budget must be zero or between 1073741824 and 8589934592 bytes", "newInboundBlockBudget(%d) = (%v, %v)", value, b, err)
		requireOrdinaryError(t, err)
	}
}

func mustReserve(t *testing.T, b *inboundBlockBudget, charge uint64) *inboundBlockLease {
	t.Helper()
	lease, err := b.TryReserveOrSubscribe(charge)
	requireTrue(t, lease != nil && err == nil, "TryReserveOrSubscribe(%d) = (%v, %v)", charge, lease, err)
	return lease
}

func usedBytes(b *inboundBlockBudget) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

func requireUsed(t *testing.T, b *inboundBlockBudget, want uint64) {
	t.Helper()
	got := usedBytes(b)
	requireTrue(t, got == want, "used = %d, want %d", got, want)
}

func generationOf(b *inboundBlockBudget) <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gen
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// requireSilentReplace pins that a replacement freeing no capacity keeps the same open
// generation.
func requireSilentReplace(t *testing.T, charge, newCharge uint64) {
	t.Helper()
	b := newTestBudget(t, 1073741824)
	lease := mustReserve(t, b, charge)
	gen := generationOf(b)
	err := b.ReplaceOrSubscribe(lease, newCharge)
	requireTrue(t, err == nil, "replacement %d -> %d refused: %v", charge, newCharge, err)
	requireTrue(t, !isClosed(gen) && generationOf(b) == gen, "replacement %d -> %d published capacity", charge, newCharge)
	requireUsed(t, b, newCharge)
}

func isCapacityRefusal(err error) bool {
	var refusal inboundBlockBudgetError
	return errors.As(err, &refusal) && refusal.Resource() == "inbound_budget_capacity"
}

func requireCapacityRefusal(t *testing.T, err error) inboundBlockBudgetError {
	t.Helper()
	var refusal inboundBlockBudgetError
	requireTrue(t, errors.As(err, &refusal) && refusal.Resource() == "inbound_budget_capacity", "expected a capacity refusal, got %v", err)
	return refusal
}

// assertResourceTuple checks the four public observations of one resource error.
func assertResourceTuple(t *testing.T, err error, wantText, wantResource string, wantNotify, wantHash bool) inboundBlockBudgetError {
	t.Helper()
	var resource inboundBlockBudgetError
	requireTrue(t, errors.As(err, &resource), "error %v is not a budget resource error", err)
	requireTrue(t, err.Error() == wantText && resource.Resource() == wantResource, "resource error = (%q, %q), want (%q, %q)", err.Error(), resource.Resource(), wantText, wantResource)
	hash, ok := resource.BlockHash()
	requireTrue(t, (resource.Notification() != nil) == wantNotify && ok == wantHash && (wantHash || hash == [32]byte{}), "notification=%v BlockHash=(%x, %v), want notification %v and hash presence %v", resource.Notification() != nil, hash, ok, wantNotify, wantHash)
	return resource
}

// requireOrdinaryError pins that caller misuse is reported as a plain error.
func requireOrdinaryError(t *testing.T, err error) {
	t.Helper()
	var resource inboundBlockBudgetError
	requireTrue(t, !errors.As(err, &resource), "caller-misuse error %v is a resource error", err)
}

func requireInvalidLease(t *testing.T, err error, label string) {
	t.Helper()
	requireTrue(t, err != nil && err.Error() == "invalid inbound block lease" && errors.Is(err, errInboundBlockLease), "%s lease replacement returned %v", label, err)
	requireOrdinaryError(t, err)
}

func replaceWithoutPanic(t *testing.T, b *inboundBlockBudget, lease *inboundBlockLease, newCharge uint64) error {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ReplaceOrSubscribe panicked: %v", r)
		}
	}()
	return b.ReplaceOrSubscribe(lease, newCharge)
}

func releaseWithoutPanic(t *testing.T, lease *inboundBlockLease) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Release panicked: %v", r)
		}
	}()
	lease.Release()
}

// allocBytesPerOp reports the heap bytes one call of op allocates.
func allocBytesPerOp(t *testing.T, op func()) int64 {
	t.Helper()
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			op()
		}
	})
	requireTrue(t, result.N > 0, "benchmark did not execute")
	return result.AllocedBytesPerOp()
}
