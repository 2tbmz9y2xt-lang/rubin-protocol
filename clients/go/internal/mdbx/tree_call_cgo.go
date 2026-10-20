//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import "runtime"

// treeUnwindV1 records how a provider call or a locked operation ended.
type treeUnwindV1 struct {
	kind  uint8 // 0 none, 1 panic, 2 goexit
	value any   // the recovered panic value, unchanged
}

// treeCallV1 runs call in the current goroutine. Normal return: (kind 0, err). A panic is recovered at the call site:
// (kind 1 value, nil). runtime.Goexit inside call cannot be stopped: treeCallV1 does not return, and the goroutine's
// deferred functions run (including runTreeLockedV1's delivery). nil call yields kind 1 with the runtime error value.
func treeCallV1(call func() error) (unwind treeUnwindV1, err error) {
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

// runTreeLockedV1 runs op on a fresh goroutine locked to its OS thread. One deferred top-level function delivers exactly
// one (outcome, unwind): normal return -> (*out, op's unwind); Goexit -> (*out as op's deferred cleanup set it, kind 2);
// a panic op did not recover is re-raised in the worker (engine defect, D4 T5). If out.poisoned the thread stays
// locked and parks (select {}) after delivery (runLocked law, mdbx_cgo.go:4057-4070). op must set *out before every
// normal return and in its deferred cleanup.
func runTreeLockedV1(op func(out *transactionOutcome) treeUnwindV1) (transactionOutcome, treeUnwindV1) {
	result := make(chan treeDeliveryV1, 1)
	go func() {
		runtime.LockOSThread()
		var delivery treeDeliveryV1
		engineFault := false
		defer func() {
			if engineFault {
				return
			}
			if !delivery.outcome.poisoned {
				runtime.UnlockOSThread()
			}
			result <- delivery
			if delivery.outcome.poisoned {
				select {}
			}
		}()
		delivery.unwind.kind = 2
		completed, value := runTreeOpV1(op, &delivery)
		if !completed {
			engineFault = true
			panic(value) //nolint:forbidigo // An op panic is an engine defect: re-raised in the worker without delivery.
		}
	}()
	delivery := <-result
	return delivery.outcome, delivery.unwind
}

// runTreeOpV1 runs op once. completed is true only when op returned normally; a recovered panic returns false with
// its value; a Goexit inside op does not return.
func runTreeOpV1(op func(out *transactionOutcome) treeUnwindV1, delivery *treeDeliveryV1) (completed bool, value any) {
	func() {
		defer func() { value = recover() }()
		delivery.unwind = op(&delivery.outcome)
		completed = true
	}()
	return completed, value
}
