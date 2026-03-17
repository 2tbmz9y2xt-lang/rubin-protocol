package node

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// PVTelemetry provides bounded-cardinality counters and latency tracking for
// parallel validation (Q-PV-13). All fields use atomic operations or mutex
// protection and are safe for concurrent access from multiple goroutines.
//
// Telemetry contract:
//   - No sensitive data (tx payloads, signatures, addresses) is recorded.
//   - All counters are monotonic uint64 — bounded cardinality.
//   - Latency tracking uses nanosecond-precision durations, not wall-clock timestamps.
//   - Mismatch diagnostics are bounded by the existing PVShadowMaxSamples limit.
type PVTelemetry struct {
	// Mode tracking.
	mode atomic.Value // stores string: "off"|"shadow"|"on"

	// Block-level counters.
	blocksValidated atomic.Uint64 // total blocks processed through PV path
	blocksSkipped   atomic.Uint64 // blocks skipped (mode=off or not IBD)

	// Shadow mismatch counters (bounded cardinality by type).
	mismatchVerdict atomic.Uint64 // seq accept vs par reject or vice versa
	mismatchError   atomic.Uint64 // different error codes
	mismatchState   atomic.Uint64 // post_state_digest mismatch
	mismatchWitness atomic.Uint64 // witness_digest mismatch

	// Signature verification counters.
	sigTotal     atomic.Uint64 // total sig verifications attempted
	sigCacheHits atomic.Uint64 // sig cache hits (skipped crypto)

	// Worker pool counters.
	workerTasksTotal atomic.Uint64 // total tasks dispatched to workers
	workerPanics     atomic.Uint64 // recovered panics in workers

	// Latency tracking (nanoseconds).
	mu                  sync.Mutex
	validateLatencyNs   []int64 // bounded ring buffer for recent validate latencies
	commitLatencyNs     []int64 // bounded ring buffer for recent commit latencies
	latencyRingCapacity int
	validateIdx         int
	commitIdx           int
	validateCount       int64
	commitCount         int64
	validateSumNs       int64
	commitSumNs         int64
}

const defaultLatencyRingCapacity = 128

// NewPVTelemetry creates a new PV telemetry instance with the given mode.
func NewPVTelemetry(mode string) *PVTelemetry {
	t := &PVTelemetry{
		latencyRingCapacity: defaultLatencyRingCapacity,
		validateLatencyNs:   make([]int64, defaultLatencyRingCapacity),
		commitLatencyNs:     make([]int64, defaultLatencyRingCapacity),
	}
	t.mode.Store(mode)
	return t
}

// SetMode updates the current PV mode label.
func (t *PVTelemetry) SetMode(mode string) {
	if t == nil {
		return
	}
	t.mode.Store(mode)
}

// Mode returns the current PV mode.
func (t *PVTelemetry) Mode() string {
	if t == nil {
		return "off"
	}
	v, ok := t.mode.Load().(string)
	if !ok || v == "" {
		return "off"
	}
	return v
}

// RecordBlockValidated increments the blocks-validated counter.
func (t *PVTelemetry) RecordBlockValidated() {
	if t == nil {
		return
	}
	t.blocksValidated.Add(1)
}

// RecordBlockSkipped increments the blocks-skipped counter.
func (t *PVTelemetry) RecordBlockSkipped() {
	if t == nil {
		return
	}
	t.blocksSkipped.Add(1)
}

// RecordMismatchVerdict increments the verdict mismatch counter.
func (t *PVTelemetry) RecordMismatchVerdict() {
	if t == nil {
		return
	}
	t.mismatchVerdict.Add(1)
}

// RecordMismatchError increments the error-code mismatch counter.
func (t *PVTelemetry) RecordMismatchError() {
	if t == nil {
		return
	}
	t.mismatchError.Add(1)
}

// RecordMismatchState increments the post-state-digest mismatch counter.
func (t *PVTelemetry) RecordMismatchState() {
	if t == nil {
		return
	}
	t.mismatchState.Add(1)
}

// RecordMismatchWitness increments the witness-digest mismatch counter.
func (t *PVTelemetry) RecordMismatchWitness() {
	if t == nil {
		return
	}
	t.mismatchWitness.Add(1)
}

// RecordSigs records a batch of signature verification operations.
func (t *PVTelemetry) RecordSigs(total, cacheHits uint64) {
	if t == nil {
		return
	}
	t.sigTotal.Add(total)
	t.sigCacheHits.Add(cacheHits)
}

// RecordWorkerTasks records the number of tasks dispatched to the worker pool.
func (t *PVTelemetry) RecordWorkerTasks(n uint64) {
	if t == nil {
		return
	}
	t.workerTasksTotal.Add(n)
}

// RecordWorkerPanic increments the worker panic counter.
func (t *PVTelemetry) RecordWorkerPanic() {
	if t == nil {
		return
	}
	t.workerPanics.Add(1)
}

// RecordValidateLatency records a validation phase latency.
func (t *PVTelemetry) RecordValidateLatency(d time.Duration) {
	if t == nil {
		return
	}
	ns := d.Nanoseconds()
	t.mu.Lock()
	t.validateLatencyNs[t.validateIdx%t.latencyRingCapacity] = ns
	t.validateIdx++
	t.validateCount++
	t.validateSumNs += ns
	t.mu.Unlock()
}

// RecordCommitLatency records a commit phase latency.
func (t *PVTelemetry) RecordCommitLatency(d time.Duration) {
	if t == nil {
		return
	}
	ns := d.Nanoseconds()
	t.mu.Lock()
	t.commitLatencyNs[t.commitIdx%t.latencyRingCapacity] = ns
	t.commitIdx++
	t.commitCount++
	t.commitSumNs += ns
	t.mu.Unlock()
}

// PVTelemetrySnapshot is a point-in-time copy of all telemetry counters.
// All fields are plain values — no sensitive data, no unbounded strings.
type PVTelemetrySnapshot struct {
	Mode string

	BlocksValidated uint64
	BlocksSkipped   uint64

	MismatchVerdict uint64
	MismatchError   uint64
	MismatchState   uint64
	MismatchWitness uint64

	SigTotal     uint64
	SigCacheHits uint64

	WorkerTasksTotal uint64
	WorkerPanics     uint64

	ValidateCount     int64
	ValidateAvgNs     int64
	CommitCount       int64
	CommitAvgNs       int64
}

// Snapshot returns a point-in-time copy of all telemetry counters.
func (t *PVTelemetry) Snapshot() PVTelemetrySnapshot {
	if t == nil {
		return PVTelemetrySnapshot{Mode: "off"}
	}
	s := PVTelemetrySnapshot{
		Mode:             t.Mode(),
		BlocksValidated:  t.blocksValidated.Load(),
		BlocksSkipped:    t.blocksSkipped.Load(),
		MismatchVerdict:  t.mismatchVerdict.Load(),
		MismatchError:    t.mismatchError.Load(),
		MismatchState:    t.mismatchState.Load(),
		MismatchWitness:  t.mismatchWitness.Load(),
		SigTotal:         t.sigTotal.Load(),
		SigCacheHits:     t.sigCacheHits.Load(),
		WorkerTasksTotal: t.workerTasksTotal.Load(),
		WorkerPanics:     t.workerPanics.Load(),
	}
	t.mu.Lock()
	s.ValidateCount = t.validateCount
	if t.validateCount > 0 {
		s.ValidateAvgNs = t.validateSumNs / t.validateCount
	}
	s.CommitCount = t.commitCount
	if t.commitCount > 0 {
		s.CommitAvgNs = t.commitSumNs / t.commitCount
	}
	t.mu.Unlock()
	return s
}

// PrometheusLines returns the telemetry snapshot as Prometheus-compatible
// text exposition lines. All metric names use the rubin_pv_ prefix.
func (s PVTelemetrySnapshot) PrometheusLines() []string {
	return []string{
		"# HELP rubin_pv_mode Current parallel validation mode (0=off, 1=shadow, 2=on).",
		"# TYPE rubin_pv_mode gauge",
		fmt.Sprintf("rubin_pv_mode{mode=%q} 1", s.Mode),

		"# HELP rubin_pv_blocks_validated_total Blocks processed through PV path.",
		"# TYPE rubin_pv_blocks_validated_total counter",
		fmt.Sprintf("rubin_pv_blocks_validated_total %d", s.BlocksValidated),

		"# HELP rubin_pv_blocks_skipped_total Blocks skipped (mode=off or not in IBD).",
		"# TYPE rubin_pv_blocks_skipped_total counter",
		fmt.Sprintf("rubin_pv_blocks_skipped_total %d", s.BlocksSkipped),

		"# HELP rubin_pv_shadow_mismatches_total Shadow mismatch count by type.",
		"# TYPE rubin_pv_shadow_mismatches_total counter",
		fmt.Sprintf("rubin_pv_shadow_mismatches_total{type=\"verdict\"} %d", s.MismatchVerdict),
		fmt.Sprintf("rubin_pv_shadow_mismatches_total{type=\"error\"} %d", s.MismatchError),
		fmt.Sprintf("rubin_pv_shadow_mismatches_total{type=\"state\"} %d", s.MismatchState),
		fmt.Sprintf("rubin_pv_shadow_mismatches_total{type=\"witness\"} %d", s.MismatchWitness),

		"# HELP rubin_pv_sig_total Total signature verifications attempted.",
		"# TYPE rubin_pv_sig_total counter",
		fmt.Sprintf("rubin_pv_sig_total %d", s.SigTotal),

		"# HELP rubin_pv_sig_cache_hits_total Signature cache hits (skipped crypto).",
		"# TYPE rubin_pv_sig_cache_hits_total counter",
		fmt.Sprintf("rubin_pv_sig_cache_hits_total %d", s.SigCacheHits),

		"# HELP rubin_pv_worker_tasks_total Tasks dispatched to worker pool.",
		"# TYPE rubin_pv_worker_tasks_total counter",
		fmt.Sprintf("rubin_pv_worker_tasks_total %d", s.WorkerTasksTotal),

		"# HELP rubin_pv_worker_panics_total Recovered panics in worker pool.",
		"# TYPE rubin_pv_worker_panics_total counter",
		fmt.Sprintf("rubin_pv_worker_panics_total %d", s.WorkerPanics),

		"# HELP rubin_pv_validate_latency_avg_ns Average validation phase latency (ns).",
		"# TYPE rubin_pv_validate_latency_avg_ns gauge",
		fmt.Sprintf("rubin_pv_validate_latency_avg_ns %d", s.ValidateAvgNs),

		"# HELP rubin_pv_commit_latency_avg_ns Average commit phase latency (ns).",
		"# TYPE rubin_pv_commit_latency_avg_ns gauge",
		fmt.Sprintf("rubin_pv_commit_latency_avg_ns %d", s.CommitAvgNs),
	}
}
