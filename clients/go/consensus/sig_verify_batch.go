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
	suiteID   uint8
	pubkey    []byte
	sig       []byte
	digest    [32]byte
	errOnFail error // error to return if this verification fails
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

// Len returns the number of pending verification tasks.
func (q *SigCheckQueue) Len() int {
	if q == nil {
		return 0
	}
	return len(q.tasks)
}

// Panics returns the number of panics recovered during the last Flush.
func (q *SigCheckQueue) Panics() uint64 {
	if q == nil {
		return 0
	}
	return q.panics.Load()
}

// Flush verifies all queued signatures in parallel and returns the first error
// (by submission order) if any verification fails. Returns nil if all signatures
// are valid.
//
// After Flush, the queue is empty and can be reused.
//
// Error ordering: the first recorded error by submission order is returned.
// The early-abort flag means some higher-index tasks may be skipped, so the
// returned error may not be the absolute lowest failing index if a lower-index
// task was skipped due to concurrency. This is acceptable because:
//   - The queue is only used during IBD, where error ordering is not consensus-critical
//   - Both paths (sequential and parallel) agree on accept/reject outcomes
//   - The block IS invalid regardless of which signature error is surfaced
func (q *SigCheckQueue) Flush() error {
	if q == nil || len(q.tasks) == 0 {
		return nil
	}
	defer func() { q.tasks = q.tasks[:0] }()

	n := len(q.tasks)

	// Single task: verify inline to avoid goroutine overhead.
	if n == 1 {
		t := q.tasks[0]
		if q.cache != nil && q.cache.Lookup(t.suiteID, t.pubkey, t.sig, t.digest) {
			return nil // cache hit — previously verified valid
		}
		var ok bool
		var err error
		ok, err = verifySigWithRegistry(t.suiteID, t.pubkey, t.sig, t.digest, q.registry)
		if err != nil {
			return err
		}
		if !ok {
			return t.errOnFail
		}
		if q.cache != nil {
			q.cache.Insert(t.suiteID, t.pubkey, t.sig, t.digest)
		}
		return nil
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

	results := make([]error, n)
	var wg sync.WaitGroup
	var anyFailed atomic.Bool // early-abort: skip remaining sigs after first failure

	taskCh := make(chan int, n)
	for i := 0; i < n; i++ {
		taskCh <- i
	}
	close(taskCh)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var currentIdx int
			defer func() {
				if r := recover(); r != nil {
					q.panics.Add(1)
					results[currentIdx] = txerr(TX_ERR_SIG_INVALID, "signature worker panic (fail-closed)")
					anyFailed.Store(true)
				}
			}()
			for idx := range taskCh {
				currentIdx = idx
				if anyFailed.Load() {
					continue // drain channel without expensive crypto work
				}
				t := q.tasks[idx]
				// Cache lookup: skip expensive crypto if previously verified valid.
				if q.cache != nil && q.cache.Lookup(t.suiteID, t.pubkey, t.sig, t.digest) {
					continue // cache hit — valid
				}
				var ok bool
				var err error
				ok, err = verifySigWithRegistry(t.suiteID, t.pubkey, t.sig, t.digest, q.registry)
				if err != nil {
					results[idx] = err
					anyFailed.Store(true)
				} else if !ok {
					results[idx] = t.errOnFail
					anyFailed.Store(true)
				} else if q.cache != nil {
					q.cache.Insert(t.suiteID, t.pubkey, t.sig, t.digest)
				}
				// results[idx] remains nil if valid
			}
		}()
	}

	wg.Wait()

	// Return first error by submission order (deterministic).
	for _, err := range results {
		if err != nil {
			return err
		}
	}
	return nil
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
