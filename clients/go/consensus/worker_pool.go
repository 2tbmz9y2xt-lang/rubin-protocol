package consensus

import (
	"context"
	"fmt"
	"runtime"
	"sync"
)

// WorkerPool executes a batch of typed tasks in parallel using a bounded
// goroutine pool. Results are returned in submission order regardless of
// scheduling, ensuring deterministic output for consensus-critical pipelines.
//
// The pool is single-use: call Run once. For repeated batches, create a new
// pool each time.
//
// Design properties:
//   - Bounded: at most MaxWorkers goroutines are active simultaneously.
//   - Deterministic: result[i] corresponds to task[i].
//   - Panic-safe: a panicking task produces an error result, does not crash
//     the process, and does not prevent other tasks from completing.
//   - Cancellable: if the context is cancelled, unstarted tasks are skipped
//     and their results are set to the context error.
type WorkerPool[T any, R any] struct {
	// MaxWorkers is the maximum number of concurrent goroutines.
	// If <= 0, defaults to GOMAXPROCS.
	MaxWorkers int

	// Func is the work function applied to each task. It receives a context
	// (for cancellation) and the task value, and returns a result or error.
	Func func(ctx context.Context, task T) (R, error)
}

// WorkerResult holds the outcome of a single task execution.
type WorkerResult[R any] struct {
	Value R
	Err   error
}

// Run executes all tasks in parallel and returns results in submission order.
// The returned slice has the same length as tasks.
//
// If ctx is cancelled, unstarted tasks receive ctx.Err() as their error.
// Already-running tasks continue to completion (Go goroutines cannot be
// forcibly stopped).
//
// If a task panics, the panic is recovered and converted to an error result.
// Other tasks are unaffected.
func (p *WorkerPool[T, R]) Run(ctx context.Context, tasks []T) []WorkerResult[R] {
	n := len(tasks)
	if n == 0 {
		return nil
	}

	workers := p.MaxWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
		if workers < 1 {
			workers = 1
		}
	}
	if workers > n {
		workers = n
	}

	results := make([]WorkerResult[R], n)

	// Single task: run inline to avoid goroutine overhead.
	if n == 1 {
		results[0] = p.execTask(ctx, tasks[0])
		return results
	}

	// Fan out via buffered channel of indices.
	taskCh := make(chan int, n)
	for i := 0; i < n; i++ {
		taskCh <- i
	}
	close(taskCh)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range taskCh {
				results[idx] = p.execTask(ctx, tasks[idx])
			}
		}()
	}

	wg.Wait()
	return results
}

// execTask runs a single task with panic recovery and context check.
func (p *WorkerPool[T, R]) execTask(ctx context.Context, task T) (result WorkerResult[R]) {
	// Check context before starting expensive work.
	if err := ctx.Err(); err != nil {
		result.Err = err
		return
	}

	defer func() {
		if r := recover(); r != nil {
			result.Err = fmt.Errorf("worker panic: %v", r)
		}
	}()

	val, err := p.Func(ctx, task)
	result.Value = val
	result.Err = err
	return
}

// RunFunc is a convenience function that creates a WorkerPool and runs tasks
// in a single call. Useful when pool reuse is not needed.
func RunFunc[T any, R any](
	ctx context.Context,
	maxWorkers int,
	tasks []T,
	fn func(ctx context.Context, task T) (R, error),
) []WorkerResult[R] {
	pool := &WorkerPool[T, R]{
		MaxWorkers: maxWorkers,
		Func:       fn,
	}
	return pool.Run(ctx, tasks)
}

// FirstError returns the first error (by index) from a slice of WorkerResults,
// or nil if all succeeded. This is useful for fail-fast consensus pipelines
// where the lowest-index error is canonical.
func FirstError[R any](results []WorkerResult[R]) error {
	for _, r := range results {
		if r.Err != nil {
			return r.Err
		}
	}
	return nil
}

// CollectValues extracts the Value fields from results into a flat slice.
// If any result has an error, returns that error immediately (first by index).
func CollectValues[R any](results []WorkerResult[R]) ([]R, error) {
	values := make([]R, len(results))
	for i, r := range results {
		if r.Err != nil {
			return nil, r.Err
		}
		values[i] = r.Value
	}
	return values, nil
}
