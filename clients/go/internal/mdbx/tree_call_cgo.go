//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import "runtime"

// ---- tree_call_cgo.go and mdbx_cgo.go (owner L4) ----

// treeUnwindV1 records how a provider call or a locked operation ended.
type treeUnwindV1 struct {
	kind  uint8 // 0 none, 1 panic, 2 goexit
	value any   // the recovered panic value, unchanged
}

// treeCallV1 runs call in the current goroutine. Normal return: (kind 0, err). A panic is recovered at the call site:
// (kind 1 value, nil). runtime.Goexit inside call cannot be stopped: treeCallV1 does not return, and the goroutine's
// deferred functions run (including runTreeLockedV1's delivery); a panic that call's own deferred functions raise
// while that Goexit unwinds is recovered here, the Goexit continues and the value is not carried. nil call yields
// kind 1 with the runtime error value.
func treeCallV1(call func() error) (treeUnwindV1, error) {
	var unwind treeUnwindV1
	var err error
	unwind.kind = 1
	func() {
		defer func() { unwind.value = recover() }()
		err = call()
		unwind.kind = 0
	}()
	return unwind, err
}

// resumeV1 runs in the caller goroutine after projection: kind 1 panic(value), kind 2 runtime.Goexit(), kind 0 nothing.
func (u treeUnwindV1) resumeV1() {
	switch u.kind {
	case 1:
		panic(u.value) //nolint:forbidigo // Caller cleanup and Store projection complete before resuming the original provider panic.
	case 2:
		runtime.Goexit()
	}
}

type treeDeliveryV1 struct {
	outcome transactionOutcome
	unwind  treeUnwindV1
}

// treeWorkerV1 is the state one runTreeLockedV1 worker owns.
type treeWorkerV1 struct {
	delivery  treeDeliveryV1
	completed bool // op returned normally
	returned  bool // control came back after op: op returned or its panic was recovered outside a Goexit
	recovered any  // the value the op-level recover returned
}

// runTreeLockedV1 runs op on a fresh goroutine locked to its OS thread. One deferred top-level function delivers exactly
// one (outcome, unwind): normal return -> (*out, op's unwind); Goexit -> (*out as op's deferred cleanup set it, kind 2);
// a panic op did not recover is re-raised in the worker without delivery (engine defect, D4 T5), also one raised while
// a Goexit unwinds, except two for which recover returns nil (a nil one under GODEBUG=panicnil=1 raised then, and one that a
// Goexit called by op's own deferred function supersedes): those are delivered as the Goexit. If out.poisoned the
// thread stays locked and parks (select {}) after delivery (runLocked law, mdbx_cgo.go:4057-4070 at base ed0e0d1b).
// op must set *out before every normal return and in its deferred cleanup.
func runTreeLockedV1(op func(out *transactionOutcome) treeUnwindV1) (transactionOutcome, treeUnwindV1) {
	result := make(chan treeDeliveryV1, 1)
	go func() {
		runtime.LockOSThread()
		var worker treeWorkerV1
		defer func() {
			if !worker.completed && (worker.returned || worker.recovered != nil) {
				panic(worker.recovered) //nolint:forbidigo // An op panic is an engine defect: re-raised in the worker without delivery.
			}
			if !worker.delivery.outcome.poisoned {
				runtime.UnlockOSThread()
			}
			result <- worker.delivery
			if worker.delivery.outcome.poisoned {
				select {}
			}
		}()
		worker.delivery.unwind.kind = 2
		runTreeOpV1(op, &worker)
		worker.returned = true
	}()
	delivery := <-result
	return delivery.outcome, delivery.unwind
}

// runTreeOpV1 runs op once and records how it ended. A recovered panic returns to the caller; while a Goexit unwinds
// the runtime continues the Goexit instead, so the recovered value is recorded for the delivery function.
func runTreeOpV1(op func(out *transactionOutcome) treeUnwindV1, worker *treeWorkerV1) {
	defer func() { worker.recovered = recover() }()
	worker.delivery.unwind = op(&worker.delivery.outcome)
	worker.completed = true
}
