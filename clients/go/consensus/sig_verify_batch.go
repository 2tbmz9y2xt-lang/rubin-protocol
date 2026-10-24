package consensus

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// SigCheckQueue collects deferred signature verification tasks during
// sequential transaction validation. When flushed, it verifies all collected
// signatures in parallel using a goroutine pool, then returns the first error
// (by submission order) if any verification fails.
//
// This implements the "check queue" pattern (analogous to Bitcoin Core's
// CCheckQueue) to parallelize the expensive ML-DSA-87 signature verification
// while preserving deterministic error ordering.
//
// Usage:
//
//	queue := NewSigCheckQueue(0) // 0 = use GOMAXPROCS workers
//	// ... during validation, call queue-aware verify functions ...
//	if err := queue.Flush(); err != nil {
//	    return err // first error by submission order
//	}
type SigCheckQueue struct {
	tasks    []sigCheckTask
	workers  int
	cache    *SigCache      // optional; positive-only sig cache (Q-PV-07)
	registry *SuiteRegistry // optional; when set, Flush uses verifySigWithRegistry for rotation-aware dispatch
	panics   atomic.Uint64
}

type sigCheckTask struct {
	suiteID    uint8
	pubkey     []byte
	sig        []byte
	digest     [32]byte
	errOnFail  error // error to return if this verification fails
	settled    bool
	err        error
	panicValue any
	panicked   bool
}

type sigCheckQueueMark struct {
	len int
}

// NewSigCheckQueue creates a new signature check queue.
// If workers <= 0, defaults to GOMAXPROCS.
func NewSigCheckQueue(workers int) *SigCheckQueue {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}
	return &SigCheckQueue{workers: workers}
}

// WithCache attaches a positive-only signature cache to the queue.
// Cached tuples are skipped during Flush (cache hit = valid).
// Returns the queue for chaining.
func (q *SigCheckQueue) WithCache(c *SigCache) *SigCheckQueue {
	q.cache = c
	return q
}

// WithRegistry attaches a suite registry for rotation-aware verification during Flush.
// When set, Flush uses verifySigWithRegistry instead of verifySig so queued tasks
// from native spend suites (e.g. post-rotation) verify correctly.
// Returns the queue for chaining.
func (q *SigCheckQueue) WithRegistry(registry *SuiteRegistry) *SigCheckQueue {
	q.registry = registry
	return q
}

// Push adds a signature verification task to the queue.
// The errOnFail is the error returned if this particular verification fails.
// If errOnFail is nil, a default TX_ERR_SIG_INVALID error is substituted to
// ensure fail-closed behavior — an invalid signature can never silently succeed.
func (q *SigCheckQueue) Push(suiteID uint8, pubkey, sig []byte, digest [32]byte, errOnFail error) {
	if errOnFail == nil {
		errOnFail = txerr(TX_ERR_SIG_INVALID, "signature verification failed (fail-closed default)")
	}
	// Defensive copy: verification is deferred until Flush (and then concurrent),
	// so we must own the data to prevent TOCTOU if callers reuse buffers.
	q.tasks = append(q.tasks, sigCheckTask{
		suiteID:   suiteID,
		pubkey:    append([]byte(nil), pubkey...),
		sig:       append([]byte(nil), sig...),
		digest:    digest,
		errOnFail: errOnFail,
	})
}

// Len returns the number of retained verification tasks, including settled tasks.
func (q *SigCheckQueue) Len() int {
	if q == nil {
		return 0
	}
	return len(q.tasks)
}

func (q *SigCheckQueue) mark() sigCheckQueueMark {
	if q == nil {
		return sigCheckQueueMark{}
	}
	return sigCheckQueueMark{len: len(q.tasks)}
}

func (q *SigCheckQueue) rollbackTo(mark sigCheckQueueMark) {
	if q == nil || mark.len >= len(q.tasks) {
		return
	}
	clear(q.tasks[mark.len:])
	q.tasks = q.tasks[:mark.len]
}

// Panics returns the cumulative number of panics projected by multi-task Flush.
func (q *SigCheckQueue) Panics() uint64 {
	if q == nil {
		return 0
	}
	return q.panics.Load()
}

// evaluate records a task's original terminal outcome once. Each active worker
// owns a distinct index; queue selection and mutation are externally confined.
func (q *SigCheckQueue) evaluate(index int) {
	t := &q.tasks[index]
	if t.settled {
		return
	}
	completed := false
	defer func() {
		if !completed {
			t.panicValue = recover()
			t.panicked = true
		}
		t.settled = true
	}()
	if q.cache != nil && q.cache.Lookup(t.suiteID, t.pubkey, t.sig, t.digest) {
		completed = true
		return
	}
	ok, err := verifySigWithRegistry(t.suiteID, t.pubkey, t.sig, t.digest, q.registry)
	switch {
	case err != nil:
		t.err = err
	case !ok:
		t.err = t.errOnFail
	case q.cache != nil:
		q.cache.Insert(t.suiteID, t.pubkey, t.sig, t.digest)
	}
	completed = true
}

// settleRange selects an already-produced interval without consuming it. Only
// its needed ascending prefix is evaluated; raw panics remain raw panics.
func (q *SigCheckQueue) settleRange(start, end sigCheckQueueMark) error {
	if start.len < 0 || end.len < start.len || end.len > q.Len() {
		panic("invalid signature queue range") //nolint:forbidigo // RUB-721: reject an invalid private range before task effects.
	}
	for i := start.len; i < end.len; i++ {
		q.evaluate(i)
		t := &q.tasks[i]
		if t.panicked {
			panic(t.panicValue) //nolint:forbidigo // RUB-721: propagate the original memoized raw panic.
		}
		if t.err != nil {
			return t.err
		}
	}
	return nil
}

// Flush completes every pending task, joins its workers and selects by original
// submission index. The full entry cardinality determines panic policy: one
// task propagates its raw panic; multiple tasks use the legacy fail-closed error.
// All consumed task references are cleared, including on raw panic propagation.
func (q *SigCheckQueue) Flush() error {
	if q == nil || len(q.tasks) == 0 {
		return nil
	}
	defer q.rollbackTo(sigCheckQueueMark{})

	n := len(q.tasks)

	// Single task: verify inline to avoid goroutine overhead.
	if n == 1 {
		return q.settleRange(sigCheckQueueMark{}, q.mark())
	}

	// Multiple tasks: fan out across workers.
	// Normalize workers defensively — a zero-value SigCheckQueue (not created
	// via NewSigCheckQueue) must not silently skip verification.
	workers := q.workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
		if workers < 1 {
			workers = 1
		}
	}
	if workers > n {
		workers = n
	}

	var wg sync.WaitGroup

	taskCh := make(chan int, n)
	for i := 0; i < n; i++ {
		taskCh <- i
	}
	close(taskCh)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range taskCh {
				q.evaluate(idx)
			}
		}()
	}

	wg.Wait()

	// Return first error by submission order (deterministic).
	var first error
	for i := range q.tasks {
		t := &q.tasks[i]
		err := t.err
		if t.panicked {
			q.panics.Add(1)
			err = txerr(TX_ERR_SIG_INVALID, "signature worker panic (fail-closed)")
		}
		if first == nil {
			first = err
		}
	}
	return first
}

// AssertFlushed returns an error if the queue has unflushed tasks. This is a
// defensive postcondition for testing that no deferred signature checks were
// silently skipped. In production, callers must call Flush() explicitly before
// accepting a block — the block validation flow guarantees this structurally.
func (q *SigCheckQueue) AssertFlushed() error {
	if q == nil {
		return nil
	}
	if len(q.tasks) > 0 {
		return txerr(TX_ERR_SIG_INVALID, "SigCheckQueue has unflushed tasks — signature bypass risk")
	}
	return nil
}
