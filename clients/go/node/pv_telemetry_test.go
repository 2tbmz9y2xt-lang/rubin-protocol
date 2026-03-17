package node

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPVTelemetry_NewAndDefaults(t *testing.T) {
	tel := NewPVTelemetry("shadow")
	if tel.Mode() != "shadow" {
		t.Fatalf("mode=%q, want shadow", tel.Mode())
	}
	s := tel.Snapshot()
	if s.Mode != "shadow" {
		t.Fatalf("snapshot mode=%q, want shadow", s.Mode)
	}
	if s.BlocksValidated != 0 || s.BlocksSkipped != 0 {
		t.Fatalf("expected zero counters, got validated=%d skipped=%d", s.BlocksValidated, s.BlocksSkipped)
	}
	if s.MismatchVerdict != 0 || s.MismatchError != 0 || s.MismatchState != 0 || s.MismatchWitness != 0 {
		t.Fatalf("expected zero mismatch counters")
	}
	if s.SigTotal != 0 || s.SigCacheHits != 0 {
		t.Fatalf("expected zero sig counters")
	}
}

func TestPVTelemetry_NilSafe(t *testing.T) {
	var tel *PVTelemetry
	// All methods must be nil-safe.
	tel.SetMode("on")
	tel.RecordBlockValidated()
	tel.RecordBlockSkipped()
	tel.RecordMismatchVerdict()
	tel.RecordMismatchError()
	tel.RecordMismatchState()
	tel.RecordMismatchWitness()
	tel.RecordSigs(10, 5)
	tel.RecordWorkerTasks(3)
	tel.RecordWorkerPanic()
	tel.RecordValidateLatency(time.Millisecond)
	tel.RecordCommitLatency(time.Millisecond)

	if tel.Mode() != "off" {
		t.Fatalf("nil mode=%q, want off", tel.Mode())
	}
	s := tel.Snapshot()
	if s.Mode != "off" {
		t.Fatalf("nil snapshot mode=%q, want off", s.Mode)
	}
}

func TestPVTelemetry_Counters(t *testing.T) {
	tel := NewPVTelemetry("on")

	tel.RecordBlockValidated()
	tel.RecordBlockValidated()
	tel.RecordBlockSkipped()
	tel.RecordMismatchVerdict()
	tel.RecordMismatchError()
	tel.RecordMismatchError()
	tel.RecordMismatchState()
	tel.RecordMismatchWitness()
	tel.RecordSigs(100, 30)
	tel.RecordWorkerTasks(50)
	tel.RecordWorkerPanic()

	s := tel.Snapshot()
	if s.BlocksValidated != 2 {
		t.Fatalf("blocks_validated=%d, want 2", s.BlocksValidated)
	}
	if s.BlocksSkipped != 1 {
		t.Fatalf("blocks_skipped=%d, want 1", s.BlocksSkipped)
	}
	if s.MismatchVerdict != 1 {
		t.Fatalf("mismatch_verdict=%d, want 1", s.MismatchVerdict)
	}
	if s.MismatchError != 2 {
		t.Fatalf("mismatch_error=%d, want 2", s.MismatchError)
	}
	if s.MismatchState != 1 {
		t.Fatalf("mismatch_state=%d, want 1", s.MismatchState)
	}
	if s.MismatchWitness != 1 {
		t.Fatalf("mismatch_witness=%d, want 1", s.MismatchWitness)
	}
	if s.SigTotal != 100 {
		t.Fatalf("sig_total=%d, want 100", s.SigTotal)
	}
	if s.SigCacheHits != 30 {
		t.Fatalf("sig_cache_hits=%d, want 30", s.SigCacheHits)
	}
	if s.WorkerTasksTotal != 50 {
		t.Fatalf("worker_tasks=%d, want 50", s.WorkerTasksTotal)
	}
	if s.WorkerPanics != 1 {
		t.Fatalf("worker_panics=%d, want 1", s.WorkerPanics)
	}
}

func TestPVTelemetry_Latency(t *testing.T) {
	tel := NewPVTelemetry("shadow")
	tel.RecordValidateLatency(10 * time.Millisecond)
	tel.RecordValidateLatency(20 * time.Millisecond)
	tel.RecordCommitLatency(5 * time.Millisecond)

	s := tel.Snapshot()
	if s.ValidateCount != 2 {
		t.Fatalf("validate_count=%d, want 2", s.ValidateCount)
	}
	expectedAvg := int64((10*time.Millisecond + 20*time.Millisecond) / 2)
	if s.ValidateAvgNs != expectedAvg {
		t.Fatalf("validate_avg_ns=%d, want %d", s.ValidateAvgNs, expectedAvg)
	}
	if s.CommitCount != 1 {
		t.Fatalf("commit_count=%d, want 1", s.CommitCount)
	}
	if s.CommitAvgNs != int64(5*time.Millisecond) {
		t.Fatalf("commit_avg_ns=%d, want %d", s.CommitAvgNs, int64(5*time.Millisecond))
	}
}

func TestPVTelemetry_SetMode(t *testing.T) {
	tel := NewPVTelemetry("off")
	if tel.Mode() != "off" {
		t.Fatalf("mode=%q, want off", tel.Mode())
	}
	tel.SetMode("shadow")
	if tel.Mode() != "shadow" {
		t.Fatalf("mode=%q, want shadow", tel.Mode())
	}
	tel.SetMode("on")
	if tel.Mode() != "on" {
		t.Fatalf("mode=%q, want on", tel.Mode())
	}
}

func TestPVTelemetry_ConcurrentSafety(t *testing.T) {
	tel := NewPVTelemetry("shadow")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tel.RecordBlockValidated()
			tel.RecordMismatchVerdict()
			tel.RecordSigs(1, 0)
			tel.RecordValidateLatency(time.Microsecond)
			tel.RecordCommitLatency(time.Microsecond)
			_ = tel.Snapshot()
		}()
	}
	wg.Wait()

	s := tel.Snapshot()
	if s.BlocksValidated != 100 {
		t.Fatalf("blocks_validated=%d, want 100", s.BlocksValidated)
	}
	if s.MismatchVerdict != 100 {
		t.Fatalf("mismatch_verdict=%d, want 100", s.MismatchVerdict)
	}
	if s.SigTotal != 100 {
		t.Fatalf("sig_total=%d, want 100", s.SigTotal)
	}
}

func TestPVTelemetrySnapshot_PrometheusLines(t *testing.T) {
	tel := NewPVTelemetry("shadow")
	tel.RecordBlockValidated()
	tel.RecordMismatchState()
	tel.RecordSigs(5, 2)

	s := tel.Snapshot()
	lines := s.PrometheusLines()
	joined := strings.Join(lines, "\n")

	// Check key metrics are present.
	mustContain := []string{
		`rubin_pv_mode{mode="shadow"} 1`,
		"rubin_pv_blocks_validated_total 1",
		`rubin_pv_shadow_mismatches_total{type="state"} 1`,
		"rubin_pv_sig_total 5",
		"rubin_pv_sig_cache_hits_total 2",
	}
	for _, want := range mustContain {
		if !strings.Contains(joined, want) {
			t.Errorf("prometheus output missing %q", want)
		}
	}

	// Verify no sensitive data (wallet addresses, raw tx payloads, private keys).
	// Note: "signature" appears in metric descriptions (e.g. "signature verifications")
	// which is fine — it's the metric label, not actual signature bytes.
	for _, line := range lines {
		if strings.Contains(line, "#") {
			continue // skip help/type comments
		}
		if strings.Contains(line, "0x") || strings.Contains(line, "privkey") {
			t.Fatalf("prometheus output contains sensitive data: %s", line)
		}
	}
}

func TestPVTelemetry_LatencyRingBufferOverflow(t *testing.T) {
	tel := NewPVTelemetry("on")
	// Record more latencies than ring buffer capacity.
	for i := 0; i < defaultLatencyRingCapacity+50; i++ {
		tel.RecordValidateLatency(time.Millisecond)
	}
	s := tel.Snapshot()
	if s.ValidateCount != int64(defaultLatencyRingCapacity+50) {
		t.Fatalf("validate_count=%d, want %d", s.ValidateCount, defaultLatencyRingCapacity+50)
	}
	if s.ValidateAvgNs != int64(time.Millisecond) {
		t.Fatalf("validate_avg_ns=%d, want %d", s.ValidateAvgNs, int64(time.Millisecond))
	}
}

func TestSyncEngine_PVTelemetryAccessor(t *testing.T) {
	st := NewChainState()
	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	cfg.ParallelValidationMode = "shadow"
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	tel := engine.PVTelemetry()
	if tel == nil {
		t.Fatal("expected non-nil PVTelemetry")
	}
	if tel.Mode() != "shadow" {
		t.Fatalf("mode=%q, want shadow", tel.Mode())
	}

	// Nil engine returns nil telemetry.
	var nilEngine *SyncEngine
	if nilEngine.PVTelemetry() != nil {
		t.Fatal("expected nil telemetry for nil engine")
	}
}
