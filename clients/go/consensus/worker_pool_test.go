package consensus

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// --------------- helpers ---------------

func intIdentity(_ context.Context, v int) (int, error) {
	return v, nil
}

func intDouble(_ context.Context, v int) (int, error) {
	return v * 2, nil
}

func intFailOdd(_ context.Context, v int) (int, error) {
	if v%2 != 0 {
		return 0, fmt.Errorf("odd: %d", v)
	}
	return v, nil
}

func mustRunPool[T any, R any](
	t *testing.T,
	pool *WorkerPool[T, R],
	ctx context.Context,
	tasks []T,
) []WorkerResult[R] {
	t.Helper()
	results, err := pool.Run(ctx, tasks)
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	return results
}

// --------------- basic tests ---------------

func TestWorkerPool_Empty(t *testing.T) {
	pool := &WorkerPool[int, int]{MaxWorkers: 4, MaxTasks: 8, Func: intIdentity}
	results := mustRunPool(t, pool, context.Background(), nil)
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestWorkerPool_SingleTask(t *testing.T) {
	pool := &WorkerPool[int, int]{MaxWorkers: 4, MaxTasks: 8, Func: intDouble}
	results := mustRunPool(t, pool, context.Background(), []int{21})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("unexpected error: %v", results[0].Err)
	}
	if results[0].Value != 42 {
		t.Fatalf("expected 42, got %d", results[0].Value)
	}
}

func TestWorkerPool_MultipleTasksOrdered(t *testing.T) {
	pool := &WorkerPool[int, int]{MaxWorkers: 2, MaxTasks: 8, Func: intDouble}
	tasks := []int{1, 2, 3, 4, 5}
	results := mustRunPool(t, pool, context.Background(), tasks)
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("task %d: unexpected error: %v", i, r.Err)
		}
		if r.Value != tasks[i]*2 {
			t.Fatalf("task %d: expected %d, got %d", i, tasks[i]*2, r.Value)
		}
	}
}

func TestWorkerPool_ErrorPreservesOrder(t *testing.T) {
	pool := &WorkerPool[int, int]{MaxWorkers: 4, MaxTasks: 8, Func: intFailOdd}
	tasks := []int{2, 3, 4, 5, 6}
	results := mustRunPool(t, pool, context.Background(), tasks)

	// Task 0 (2): ok, Task 1 (3): error, Task 2 (4): ok, Task 3 (5): error, Task 4 (6): ok
	if results[0].Err != nil || results[0].Value != 2 {
		t.Fatalf("task 0: expected (2, nil), got (%d, %v)", results[0].Value, results[0].Err)
	}
	if results[1].Err == nil {
		t.Fatal("task 1: expected error for odd=3")
	}
	if results[2].Err != nil || results[2].Value != 4 {
		t.Fatalf("task 2: expected (4, nil), got (%d, %v)", results[2].Value, results[2].Err)
	}
	if results[3].Err == nil {
		t.Fatal("task 3: expected error for odd=5")
	}
	if results[4].Err != nil || results[4].Value != 6 {
		t.Fatalf("task 4: expected (6, nil), got (%d, %v)", results[4].Value, results[4].Err)
	}
}

func TestWorkerPool_DefaultWorkers(t *testing.T) {
	// MaxWorkers=0 → should default to GOMAXPROCS.
	pool := &WorkerPool[int, int]{MaxWorkers: 0, MaxTasks: 16, Func: intIdentity}
	tasks := make([]int, 10)
	for i := range tasks {
		tasks[i] = i
	}
	results := mustRunPool(t, pool, context.Background(), tasks)
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("task %d: %v", i, r.Err)
		}
		if r.Value != i {
			t.Fatalf("task %d: expected %d, got %d", i, i, r.Value)
		}
	}
}

func TestWorkerPool_WorkersCappedAtTaskCount(t *testing.T) {
	// 100 workers but only 3 tasks → should use 3 workers.
	var maxConcurrent atomic.Int32
	var current atomic.Int32

	pool := &WorkerPool[int, int]{
		MaxWorkers: 100,
		MaxTasks:   8,
		Func: func(_ context.Context, v int) (int, error) {
			c := current.Add(1)
			for {
				old := maxConcurrent.Load()
				if c <= old || maxConcurrent.CompareAndSwap(old, c) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			current.Add(-1)
			return v, nil
		},
	}
	tasks := []int{1, 2, 3}
	_ = mustRunPool(t, pool, context.Background(), tasks)

	mc := maxConcurrent.Load()
	if mc > 3 {
		t.Fatalf("max concurrent %d > 3 (task count)", mc)
	}
}

// --------------- panic safety ---------------

func TestWorkerPool_PanicRecovery(t *testing.T) {
	pool := &WorkerPool[int, int]{
		MaxWorkers: 2,
		MaxTasks:   8,
		Func: func(_ context.Context, v int) (int, error) {
			if v == 3 {
				panic("task 3 panicked")
			}
			return v * 10, nil
		},
	}
	tasks := []int{1, 2, 3, 4, 5}
	results := mustRunPool(t, pool, context.Background(), tasks)

	// Task 2 (value=3) should have panic error.
	if results[2].Err == nil {
		t.Fatal("expected panic error for task[2]")
	}
	if results[2].Err.Error() != fixedWorkerPanicMessage {
		t.Fatalf("unexpected panic error: %v", results[2].Err)
	}
	// Other tasks should succeed.
	for i, r := range results {
		if i == 2 {
			continue
		}
		if r.Err != nil {
			t.Fatalf("task %d: unexpected error: %v", i, r.Err)
		}
		if r.Value != tasks[i]*10 {
			t.Fatalf("task %d: expected %d, got %d", i, tasks[i]*10, r.Value)
		}
	}
}

func TestWorkerPool_PanicDoesNotLeakGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()

	pool := &WorkerPool[int, int]{
		MaxWorkers: 4,
		MaxTasks:   16,
		Func: func(_ context.Context, v int) (int, error) {
			if v%2 == 0 {
				panic(fmt.Sprintf("panic at %d", v))
			}
			return v, nil
		},
	}
	tasks := []int{1, 2, 3, 4, 5, 6, 7, 8}
	_ = mustRunPool(t, pool, context.Background(), tasks)

	// Give goroutines time to clean up.
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()

	// Allow some slack for test infrastructure goroutines.
	if after > before+2 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

// --------------- cancellation ---------------

func TestWorkerPool_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var started atomic.Int32
	pool := &WorkerPool[int, int]{
		MaxWorkers: 1, // single worker for deterministic ordering
		MaxTasks:   8,
		Func: func(ctx context.Context, v int) (int, error) {
			started.Add(1)
			if v == 2 {
				cancel() // cancel after processing task[1] (value=2)
				return v, nil
			}
			// Check context for later tasks.
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			return v * 10, nil
		},
	}

	tasks := []int{1, 2, 3, 4, 5}
	results := mustRunPool(t, pool, ctx, tasks)

	// Task 0 (value=1): should succeed.
	if results[0].Err != nil {
		t.Fatalf("task 0: %v", results[0].Err)
	}
	// Task 1 (value=2): should succeed (it's the one that cancels).
	if results[1].Err != nil {
		t.Fatalf("task 1: %v", results[1].Err)
	}
	// Tasks 2-4: should have context.Canceled errors.
	for i := 2; i < 5; i++ {
		if results[i].Err == nil {
			t.Fatalf("task %d: expected cancellation error", i)
		}
		if !errors.Is(results[i].Err, context.Canceled) {
			t.Fatalf("task %d: expected context.Canceled, got %v", i, results[i].Err)
		}
	}
}

func TestWorkerPool_AlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	pool := &WorkerPool[int, int]{MaxWorkers: 4, MaxTasks: 8, Func: intIdentity}
	tasks := []int{1, 2, 3}
	results := mustRunPool(t, pool, ctx, tasks)

	for i, r := range results {
		if r.Err == nil {
			t.Fatalf("task %d: expected error", i)
		}
		if !errors.Is(r.Err, context.Canceled) {
			t.Fatalf("task %d: expected context.Canceled, got %v", i, r.Err)
		}
	}
}

// --------------- convenience functions ---------------

func TestRunFunc(t *testing.T) {
	results, err := RunFunc(context.Background(), 2, 8, []int{10, 20, 30}, intDouble)
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	expected := []int{20, 40, 60}
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("task %d: %v", i, r.Err)
		}
		if r.Value != expected[i] {
			t.Fatalf("task %d: expected %d, got %d", i, expected[i], r.Value)
		}
	}
}

func TestFirstError(t *testing.T) {
	// No errors.
	results := []WorkerResult[int]{
		{Value: 1}, {Value: 2}, {Value: 3},
	}
	if err := FirstError(results); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	// Error at index 2.
	results[2].Err = fmt.Errorf("fail at 2")
	if err := FirstError(results); err == nil || err.Error() != "fail at 2" {
		t.Fatalf("expected 'fail at 2', got %v", err)
	}

	// Error at index 0 takes precedence.
	results[0].Err = fmt.Errorf("fail at 0")
	if err := FirstError(results); err == nil || err.Error() != "fail at 0" {
		t.Fatalf("expected 'fail at 0', got %v", err)
	}
}

func TestCollectValues(t *testing.T) {
	// All success.
	results := []WorkerResult[int]{
		{Value: 10}, {Value: 20}, {Value: 30},
	}
	vals, err := CollectValues(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, v := range vals {
		if v != (i+1)*10 {
			t.Fatalf("expected %d, got %d", (i+1)*10, v)
		}
	}

	// Error at index 1.
	results[1].Err = fmt.Errorf("bad")
	_, err = CollectValues(results)
	if err == nil || err.Error() != "bad" {
		t.Fatalf("expected 'bad', got %v", err)
	}
}

// --------------- determinism ---------------

func TestWorkerPool_DeterministicResultOrder(t *testing.T) {
	// Run 10 times with random-ish delays to verify order is always preserved.
	for iter := 0; iter < 10; iter++ {
		pool := &WorkerPool[int, int]{
			MaxWorkers: 4,
			MaxTasks:   32,
			Func: func(_ context.Context, v int) (int, error) {
				// Vary delay to expose ordering bugs.
				if v%3 == 0 {
					time.Sleep(time.Millisecond)
				}
				return v * v, nil
			},
		}
		tasks := make([]int, 20)
		for i := range tasks {
			tasks[i] = i
		}
		results := mustRunPool(t, pool, context.Background(), tasks)
		for i, r := range results {
			if r.Err != nil {
				t.Fatalf("iter %d task %d: %v", iter, i, r.Err)
			}
			if r.Value != i*i {
				t.Fatalf("iter %d task %d: expected %d, got %d", iter, i, i*i, r.Value)
			}
		}
	}
}

// --------------- bounded concurrency ---------------

func TestWorkerPool_BoundedConcurrency(t *testing.T) {
	const maxW = 3
	var current atomic.Int32
	var maxSeen atomic.Int32

	pool := &WorkerPool[int, int]{
		MaxWorkers: maxW,
		MaxTasks:   32,
		Func: func(_ context.Context, v int) (int, error) {
			c := current.Add(1)
			for {
				old := maxSeen.Load()
				if c <= old || maxSeen.CompareAndSwap(old, c) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond) // hold slot
			current.Add(-1)
			return v, nil
		},
	}
	tasks := make([]int, 20)
	for i := range tasks {
		tasks[i] = i
	}
	_ = mustRunPool(t, pool, context.Background(), tasks)

	if maxSeen.Load() > maxW {
		t.Fatalf("max concurrent %d exceeds MaxWorkers %d", maxSeen.Load(), maxW)
	}
}

// --------------- large batch ---------------

func TestWorkerPool_LargeBatch(t *testing.T) {
	const n = 1000
	pool := &WorkerPool[int, int]{MaxWorkers: 8, MaxTasks: n, Func: intDouble}
	tasks := make([]int, n)
	for i := range tasks {
		tasks[i] = i
	}
	results := mustRunPool(t, pool, context.Background(), tasks)
	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("task %d: %v", i, r.Err)
		}
		if r.Value != i*2 {
			t.Fatalf("task %d: expected %d, got %d", i, i*2, r.Value)
		}
	}
}

// --------------- negative workers ---------------

func TestWorkerPool_NegativeWorkers(t *testing.T) {
	pool := &WorkerPool[int, int]{MaxWorkers: -5, MaxTasks: 1, Func: intIdentity}
	results := mustRunPool(t, pool, context.Background(), []int{42})
	if results[0].Err != nil {
		t.Fatalf("unexpected error: %v", results[0].Err)
	}
	if results[0].Value != 42 {
		t.Fatalf("expected 42, got %d", results[0].Value)
	}
}

func TestWorkerPool_InvalidMaxTasks(t *testing.T) {
	pool := &WorkerPool[int, int]{MaxWorkers: 4, MaxTasks: 0, Func: intIdentity}
	if _, err := pool.Run(context.Background(), []int{1, 2, 3}); !errors.Is(err, ErrWorkerPoolInvalidMaxTasks) {
		t.Fatalf("expected ErrWorkerPoolInvalidMaxTasks, got %v", err)
	}
}

func TestWorkerPool_TaskCountLimit(t *testing.T) {
	pool := &WorkerPool[int, int]{MaxWorkers: 4, MaxTasks: 2, Func: intIdentity}
	_, err := pool.Run(context.Background(), []int{1, 2, 3})
	var runErr *WorkerPoolRunError
	if !errors.As(err, &runErr) {
		t.Fatalf("expected WorkerPoolRunError, got %v", err)
	}
	if runErr.TaskCount != 3 || runErr.MaxTasks != 2 {
		t.Fatalf("unexpected run error payload: %+v", runErr)
	}
}

func TestWorkerPoolRunErrorString(t *testing.T) {
	err := (&WorkerPoolRunError{TaskCount: 7, MaxTasks: 3}).Error()
	if err != "worker pool task count 7 exceeds configured limit 3" {
		t.Fatalf("unexpected error string: %q", err)
	}
}

func TestWorkerPool_NonStringPanicUsesFixedMessage(t *testing.T) {
	pool := &WorkerPool[int, int]{
		MaxWorkers: 1,
		MaxTasks:   1,
		Func: func(_ context.Context, _ int) (int, error) {
			panic(7)
		},
	}
	results := mustRunPool(t, pool, context.Background(), []int{1})
	if results[0].Err == nil {
		t.Fatal("expected panic error")
	}
	if results[0].Err.Error() != fixedWorkerPanicMessage {
		t.Fatalf("expected fixed panic message, got %v", results[0].Err)
	}
}

func TestVerifyDAChunkHashesParallel_TaskLimit(t *testing.T) {
	tasks := make([]DAChunkHashTask, int(MAX_DA_CHUNK_COUNT)+1)
	err := VerifyDAChunkHashesParallel(context.Background(), tasks, 2)
	var runErr *WorkerPoolRunError
	if !errors.As(err, &runErr) {
		t.Fatalf("expected WorkerPoolRunError, got %v", err)
	}
	if runErr.TaskCount != len(tasks) || runErr.MaxTasks != int(MAX_DA_CHUNK_COUNT) {
		t.Fatalf("unexpected chunk-limit payload: %+v", runErr)
	}
}

func TestVerifyDAPayloadCommitsParallel_TaskLimit(t *testing.T) {
	tasks := make([]DAPayloadCommitTask, int(MAX_DA_BATCHES_PER_BLOCK)+1)
	err := VerifyDAPayloadCommitsParallel(context.Background(), tasks, 2)
	var runErr *WorkerPoolRunError
	if !errors.As(err, &runErr) {
		t.Fatalf("expected WorkerPoolRunError, got %v", err)
	}
	if runErr.TaskCount != len(tasks) || runErr.MaxTasks != int(MAX_DA_BATCHES_PER_BLOCK) {
		t.Fatalf("unexpected payload-limit payload: %+v", runErr)
	}
}
