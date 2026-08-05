package node

import "fmt"

// diagnosticBatchMaxRecords and diagnosticBatchMaxBytes bound what ONE public
// SyncEngine mutation may retain for its post-unlock flush. They cap RETAINED
// diagnostic output only: no consensus, chainstate, mempool or owner data is
// bounded, dropped or reordered.
const (
	diagnosticBatchMaxRecords = 64
	diagnosticBatchMaxBytes   = 64 << 10
)

// diagnosticBatchTruncatedRecord is the ONE fixed record representing every
// dropped record of a mutation. Its content is deliberately constant: a count or
// byte total would vary with how far a timing-dependent producer got, making the
// same mutation emit different bytes across runs.
const diagnosticBatchTruncatedRecord = "sync: diagnostics truncated for this mutation; later records dropped\n"

// diagnosticBatch is the bounded diagnostic buffer owned by exactly one public
// SyncEngine mutation. Producers beneath that mutation append to it instead of
// invoking the configured writer, so a caller-supplied io.Writer that blocks or
// re-enters the engine cannot run while mutationMu, s.mu, the admission guard,
// or any ChainState / Mempool / owner lock is held. Below the caps it preserves
// producer order and per-record bytes exactly: a delay, not a rewrite.
//
// It is NOT shared: each entry point stack-allocates its own batch and passes a
// pointer down its own call tree, so no lock protects it and no second goroutine
// observes it. There is no ambient, goroutine-local or engine-global "current
// batch", and the batch confers no mutation authority.
type diagnosticBatch struct {
	records   []string
	bytes     int
	truncated bool
	flushed   bool
}

// append retains one already-formatted record, or drops it and arms the single
// truncation record. Once either cap is reached the batch is CLOSED: later
// records are dropped too, so a large record cannot be skipped in favour of a
// smaller one behind it, which would reorder what an operator reads.
func (b *diagnosticBatch) append(record string) {
	if b == nil || b.truncated {
		return
	}
	if len(b.records) >= diagnosticBatchMaxRecords || b.bytes+len(record) > diagnosticBatchMaxBytes {
		b.truncated = true
		return
	}
	b.records = append(b.records, record)
	b.bytes += len(record)
}

// diagnose emits one operator diagnostic. With a batch — every producer reached
// beneath a public mutation — the record is retained for that mutation's single
// post-unlock flush and NO caller-supplied writer runs here.
//
// With batch == nil the record is written immediately through the synchronized
// writer snapshot. That direct form is legal ONLY for a caller holding none of
// the locks in the engine's isolation contract: mutationMu, s.mu, the ChainState
// admission guard, and any ChainState / Mempool / PendingOutpointOwner lock.
// Every production producer reaches this through a batch (see the call-site
// census in sync_stderr_test.go); the direct form serves callers outside a
// mutation, which hold no engine lock by construction.
func (s *SyncEngine) diagnose(batch *diagnosticBatch, format string, args ...any) {
	record := fmt.Sprintf(format, args...)
	if batch != nil {
		batch.append(record)
		return
	}
	// fmt.Fprint with one string operand writes exactly the record's bytes in
	// one Write call, as the pre-existing fmt.Fprintf sites did.
	_, _ = fmt.Fprint(s.diagnosticWriter(), record)
}

// flushDiagnostics writes one mutation's retained records, in producer order,
// through ONE writer snapshot, and is the only place a batched record reaches a
// caller-supplied io.Writer.
//
// The caller MUST have released mutationMu and every inner canonical, admission,
// state, mempool and owner lock first; entry points arrange that by deferring
// this BEFORE they defer their mutationMu unlock, so it runs last. A writer that
// blocks here therefore delays only the originating call — another mutator
// acquires mutationMu and reaches its own result, and a writer that re-enters a
// non-diagnostic SyncEngine mutation cannot deadlock. The single exception is the
// terminal fail-closed latch, which retains the admission guard until restart by
// pre-existing design (canonicalTransition.end): that flush has mutationMu and
// s.mu free but the latch still held — nothing can acquire that guard again
// either way, and every entry point then fails closed through mutationAllowed
// without touching it.
//
// Writer errors stay best-effort — they never replace or alter the mutation
// result — and flushing is idempotent: a batch is emitted at most once.
func (s *SyncEngine) flushDiagnostics(batch *diagnosticBatch) {
	if batch == nil || batch.flushed {
		return
	}
	batch.flushed = true
	if len(batch.records) == 0 && !batch.truncated {
		return
	}
	writer := s.diagnosticWriter()
	for _, record := range batch.records {
		_, _ = fmt.Fprint(writer, record)
	}
	if batch.truncated {
		_, _ = fmt.Fprint(writer, diagnosticBatchTruncatedRecord)
	}
}
