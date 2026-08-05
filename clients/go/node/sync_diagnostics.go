package node

import (
	"fmt"
	"io"
)

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
	// terminal is the fail-closed latch record, in its OWN slot because it is the
	// one record the caps must never evict: a >=64-row reorg with systematic
	// PV-shadow mismatch fills the batch during preparation, and a capped
	// terminal record would leave stderr showing shadow noise plus a content-free
	// truncation marker while the node latched shut. It stays bounded — a fixed
	// format plus the latch cause, and canonicalTransition.end runs once.
	terminal string
}

// append retains one already-formatted record, or drops it and arms the single
// truncation record. Once either cap is reached the batch is CLOSED: later
// records are dropped too, so a large record cannot be skipped in favor of a
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
//
// As of this change the direct form has NO production caller: every production
// producer is reached beneath a public mutation and therefore carries a batch,
// and the only batch-free caller of a producer is test code (the raw-byte
// requeueDisconnectedTransactions has no production call site at all). That is a
// property of the current call graph — established by grepping every producer's
// callers, not by any mechanism here — so a new batch-free production caller
// must re-prove the lock-freedom above.
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

// diagnoseTerminal is diagnose for the ONE record class the caps may not evict:
// the fail-closed terminal-latch report. It bypasses the record and byte caps
// into the batch's dedicated slot, keeping the retained output bounded because
// exactly one terminal record exists per mutation. Everything else — the direct
// write when there is no batch, the bytes, the writer contract — is identical to
// diagnose.
func (s *SyncEngine) diagnoseTerminal(batch *diagnosticBatch, format string, args ...any) {
	record := fmt.Sprintf(format, args...)
	if batch != nil {
		batch.terminal = record
		return
	}
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
	if len(batch.records) == 0 && !batch.truncated && batch.terminal == "" {
		return
	}
	writer := s.diagnosticWriter()
	for _, record := range batch.records {
		_, _ = fmt.Fprint(writer, record)
	}
	batch.flushTail(writer)
}

// flushTail emits what follows the retained records: the truncation marker for
// anything the caps dropped, then the terminal-latch record.
//
// The terminal record goes last, which IS its producer order: it is emitted by
// canonicalTransition.end, after every other producer of that mutation (PV
// shadow runs before the transition opens, the cleanup report inside it), and
// the only producer that could follow it — the reorg requeue — is skipped
// entirely when end returns a terminal cause.
func (b *diagnosticBatch) flushTail(writer io.Writer) {
	if b.truncated {
		_, _ = fmt.Fprint(writer, diagnosticBatchTruncatedRecord)
	}
	if b.terminal != "" {
		_, _ = fmt.Fprint(writer, b.terminal)
	}
}
