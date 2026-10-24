package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// isTxErrCode checks if an error is a *TxError with the given error code.
func isTxErrCode(err error, code ErrorCode) bool {
	var te *TxError
	if !errors.As(err, &te) {
		return false
	}
	return te.Code == code
}

// mustMLDSA87KeypairB is the benchmark-compatible variant of mustMLDSA87Keypair.
func mustMLDSA87KeypairB(b *testing.B) *MLDSA87Keypair {
	b.Helper()
	kp, err := NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(err.Error(), "unsupported") {
			b.Skipf("ML-DSA backend unavailable: %v", err)
		}
		b.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	b.Cleanup(func() { kp.Close() })
	return kp
}

// ─────────────────────────────────────────────────────────────────────────────
// SigCheckQueue unit tests
// ─────────────────────────────────────────────────────────────────────────────

func TestSigCheckQueue_EmptyFlush(t *testing.T) {
	q := NewSigCheckQueue(0)
	if err := q.Flush(); err != nil {
		t.Fatalf("Flush on empty queue: %v", err)
	}
}

func TestSigCheckQueue_NilFlush(t *testing.T) {
	var q *SigCheckQueue
	if err := q.Flush(); err != nil {
		t.Fatalf("Flush on nil queue: %v", err)
	}
}

func TestSigCheckQueue_SingleValid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x42
	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	q := NewSigCheckQueue(1)
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, digest, txerr(TX_ERR_SIG_INVALID, "test"))
	if err := q.Flush(); err != nil {
		t.Fatalf("Flush valid sig: %v", err)
	}
}

func TestSigCheckQueue_SingleInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x42
	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Corrupt the digest.
	badDigest := digest
	badDigest[0] ^= 0xFF

	q := NewSigCheckQueue(1)
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, badDigest, txerr(TX_ERR_SIG_INVALID, "expected failure"))
	err = q.Flush()
	if err == nil {
		t.Fatalf("expected error from invalid sig, got nil")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestSigCheckQueue_MultipleAllValid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	const n = 8

	q := NewSigCheckQueue(4)
	for i := 0; i < n; i++ {
		var digest [32]byte
		digest[0] = byte(i)
		sig, err := kp.SignDigest32(digest)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, digest, txerr(TX_ERR_SIG_INVALID, "test"))
	}
	if q.Len() != n {
		t.Fatalf("expected %d tasks, got %d", n, q.Len())
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("Flush valid sigs: %v", err)
	}
	if q.Len() != 0 {
		t.Fatalf("expected empty queue after Flush, got %d", q.Len())
	}
}

func TestSigCheckQueue_RollbackClearsDroppedTail(t *testing.T) {
	q := NewSigCheckQueue(1)
	firstPubkey := []byte{0x01}
	firstSig := []byte{0x02}
	droppedPubkey := []byte{0x03}
	droppedSig := []byte{0x04}

	q.Push(SUITE_ID_ML_DSA_87, firstPubkey, firstSig, [32]byte{0x11}, txerr(TX_ERR_SIG_INVALID, "keep"))
	mark := q.mark()
	q.Push(SUITE_ID_ML_DSA_87, droppedPubkey, droppedSig, [32]byte{0x22}, txerr(TX_ERR_SIG_INVALID, "drop"))

	q.rollbackTo(mark)
	if q.Len() != 1 {
		t.Fatalf("expected rollback to preserve one task, got %d", q.Len())
	}
	if len(q.tasks[0].pubkey) == 0 || len(q.tasks[0].sig) == 0 || q.tasks[0].errOnFail == nil {
		t.Fatal("rollback cleared preserved task")
	}

	backing := q.tasks[:cap(q.tasks)]
	if len(backing) < 2 {
		t.Fatalf("test requires retained backing slot, got cap %d", cap(q.tasks))
	}
	dropped := backing[1]
	if dropped.pubkey != nil || dropped.sig != nil || dropped.errOnFail != nil {
		t.Fatalf("rollback retained dropped task references: pubkey=%v sig=%v err=%v", dropped.pubkey, dropped.sig, dropped.errOnFail)
	}
	if dropped.suiteID != 0 || dropped.digest != ([32]byte{}) {
		t.Fatalf("rollback retained dropped task values: suite=%d digest=%x", dropped.suiteID, dropped.digest)
	}
}

func TestSigCheckQueue_DeterministicFirstError(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	// Create 4 tasks: task 0 and 2 are invalid, task 1 and 3 are valid.
	// Flush should return task 0's error (first by submission order).
	q := NewSigCheckQueue(4)
	for i := 0; i < 4; i++ {
		var digest [32]byte
		digest[0] = byte(i)
		sig, err := kp.SignDigest32(digest)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		if i == 0 || i == 2 {
			// Corrupt the digest for tasks 0 and 2.
			digest[1] ^= 0xFF
		}
		q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, digest,
			txerr(TX_ERR_SIG_INVALID, "task-"+string(rune('0'+i))))
	}

	err := q.Flush()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
	// Verify it's from task 0 (first failing).
	te, ok := err.(*TxError)
	if !ok {
		t.Fatalf("expected *TxError, got %T", err)
	}
	if te.Msg != "task-0" {
		t.Fatalf("expected error from task-0, got: %s", te.Msg)
	}
}

func TestSigCheckQueue_ReusableAfterFlush(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	q := NewSigCheckQueue(2)

	// First batch: valid.
	var d1 [32]byte
	d1[0] = 0x01
	sig1, _ := kp.SignDigest32(d1)
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig1, d1, txerr(TX_ERR_SIG_INVALID, "batch1"))
	if err := q.Flush(); err != nil {
		t.Fatalf("batch1: %v", err)
	}

	// Second batch: invalid.
	var d2 [32]byte
	d2[0] = 0x02
	sig2, _ := kp.SignDigest32(d2)
	d2[0] ^= 0xFF // corrupt
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig2, d2, txerr(TX_ERR_SIG_INVALID, "batch2"))
	err := q.Flush()
	if err == nil {
		t.Fatalf("expected batch2 error")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Fail-closed guards
// ─────────────────────────────────────────────────────────────────────────────

func TestSigCheckQueue_NilErrOnFail_FailsClosed(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x42
	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Corrupt the digest so verification fails.
	badDigest := digest
	badDigest[0] ^= 0xFF

	q := NewSigCheckQueue(1)
	// Push with nil errOnFail — must NOT silently accept.
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, badDigest, nil)
	err = q.Flush()
	if err == nil {
		t.Fatalf("expected fail-closed error from nil errOnFail, got nil")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID from fail-closed default, got: %v", err)
	}
}

func TestSigCheckQueue_ZeroValueFlush_FailsClosed(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	// Create a zero-value queue (NOT via NewSigCheckQueue) — workers=0.
	var q SigCheckQueue

	for i := 0; i < 4; i++ {
		var d [32]byte
		d[0] = byte(i)
		sig, err := kp.SignDigest32(d)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d, txerr(TX_ERR_SIG_INVALID, "zero-value"))
	}
	// Flush must normalize workers and verify — not skip.
	if err := q.Flush(); err != nil {
		t.Fatalf("zero-value queue Flush should pass for valid sigs: %v", err)
	}

	// Now with invalid sigs: must detect.
	for i := 0; i < 4; i++ {
		var d [32]byte
		d[0] = byte(i)
		sig, err := kp.SignDigest32(d)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		d[0] ^= 0xFF // corrupt
		q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d, txerr(TX_ERR_SIG_INVALID, "zero-value-invalid"))
	}
	err := q.Flush()
	if err == nil {
		t.Fatalf("zero-value queue must detect invalid sigs, got nil")
	}
}

func TestSigCheckQueue_AssertFlushed_Unflushed(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	q := NewSigCheckQueue(1)
	var d [32]byte
	sig, _ := kp.SignDigest32(d)
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d, txerr(TX_ERR_SIG_INVALID, "test"))

	err := q.AssertFlushed()
	if err == nil {
		t.Fatalf("expected error from AssertFlushed on unflushed queue")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestSigCheckQueue_AssertFlushed_NilOK(t *testing.T) {
	var q *SigCheckQueue
	if err := q.AssertFlushed(); err != nil {
		t.Fatalf("nil queue AssertFlushed: %v", err)
	}
}

func TestSigCheckQueue_AssertFlushed_AfterFlush(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	q := NewSigCheckQueue(1)
	var d [32]byte
	sig, _ := kp.SignDigest32(d)
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d, txerr(TX_ERR_SIG_INVALID, "test"))
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := q.AssertFlushed(); err != nil {
		t.Fatalf("AssertFlushed after successful Flush: %v", err)
	}
}

func TestSigCheckQueue_Len_Nil(t *testing.T) {
	var q *SigCheckQueue
	if q.Len() != 0 {
		t.Fatalf("nil queue Len should be 0, got %d", q.Len())
	}
}

func TestSigCheckQueue_Single_BadSuiteError(t *testing.T) {
	// Push a single task with an unknown suite ID. verifySig returns an error
	// (not ok=false), which exercises the Flush single-task err!=nil path (line 94).
	q := NewSigCheckQueue(1)
	q.Push(0xFE, []byte("fake-pubkey"), []byte("fake-sig"), [32]byte{}, txerr(TX_ERR_SIG_INVALID, "test"))
	err := q.Flush()
	if err == nil {
		t.Fatalf("expected error for bad suite ID in single-task Flush")
	}
}

func TestSigCheckQueue_Multi_BadSuiteError(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	// 1 worker: deterministic sequential processing inside goroutine.
	// Task 0 returns a registry error; task 1 must still complete verification.
	q := NewSigCheckQueue(1)

	q.Push(0xFE, []byte("fake-pubkey"), []byte("fake-sig"), [32]byte{},
		txerr(TX_ERR_SIG_INVALID, "bad-suite"))

	var d [32]byte
	d[0] = 0x42
	sig, err := kp.SignDigest32(d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d,
		txerr(TX_ERR_SIG_INVALID, "valid-sig"))

	err = q.Flush()
	if err == nil {
		t.Fatalf("expected error from bad suite ID in multi-task Flush, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Parallel stress test
// ─────────────────────────────────────────────────────────────────────────────

func TestSigCheckQueue_ParallelStress(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	workers := runtime.GOMAXPROCS(0) * 2
	if workers < 4 {
		workers = 4
	}
	const n = 32

	q := NewSigCheckQueue(workers)
	for i := 0; i < n; i++ {
		var d [32]byte
		d[0] = byte(i)
		d[1] = byte(i >> 8)
		sig, err := kp.SignDigest32(d)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d, txerr(TX_ERR_SIG_INVALID, "stress"))
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("stress flush: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Queue-aware verify function tests
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyMLDSAKeyAndSigQ_NilQueue_MatchesOriginal(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	// Replace the witness with a valid sig using this keypair.
	sig := signDigestWithSighashType(t, kp, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	tx.Witness = []WitnessItem{{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp.PubkeyBytes(),
		Signature: sig,
	}}

	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	expectedKeyID := sha3_256(kp.PubkeyBytes())

	// Queue=nil should verify inline, matching the original function.
	err = verifyMLDSAKeyAndSigQ(
		tx.Witness[0], expectedKeyID, tx, inputIndex, inputValue, chainID, cache, nil, nil, "TEST",
	)
	if err != nil {
		t.Fatalf("nil queue verify: %v", err)
	}

	// Queue=non-nil should defer (not fail).
	q := NewSigCheckQueue(1)
	err = verifyMLDSAKeyAndSigQ(
		tx.Witness[0], expectedKeyID, tx, inputIndex, inputValue, chainID, cache, q, nil, "TEST",
	)
	if err != nil {
		t.Fatalf("queued verify (pre-flush): %v", err)
	}
	if q.Len() != 1 {
		t.Fatalf("expected 1 queued task, got %d", q.Len())
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("queued verify (flush): %v", err)
	}
}

func TestVerifyMLDSAKeyAndSigQ_KeyBindingMismatch(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	tx, _, _, _ := testSighashContextTx()
	tx.Witness = []WitnessItem{{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp.PubkeyBytes(),
		Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
	}}

	// Wrong key ID → should fail immediately, even with queue.
	q := NewSigCheckQueue(1)
	err := verifyMLDSAKeyAndSigQ(
		tx.Witness[0], [32]byte{0xFF}, tx, 0, 1, [32]byte{}, nil, q, nil, "TEST",
	)
	if err == nil {
		t.Fatalf("expected key binding error")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
	// Queue should be empty (error returned immediately, not deferred).
	if q.Len() != 0 {
		t.Fatalf("expected empty queue on key binding failure, got %d", q.Len())
	}
}

func TestVerifyMLDSAKeyAndSigQ_NilQueue_InvalidSig(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	sig := signDigestWithSighashType(t, kp, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	tx.Witness = []WitnessItem{{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp.PubkeyBytes(),
		Signature: sig,
	}}

	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	// Corrupt pubkey so key binding still matches but sig verification fails.
	kp2 := mustMLDSA87Keypair(t)
	expectedKeyID := sha3_256(kp2.PubkeyBytes())
	// Use kp2's pubkey (valid key binding) with kp's signature (mismatched).
	w := WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    kp2.PubkeyBytes(),
		Signature: sig,
	}

	// sigQueue=nil → verifies inline → should return invalid sig error.
	err = verifyMLDSAKeyAndSigQ(w, expectedKeyID, tx, inputIndex, inputValue, chainID, cache, nil, nil, "TEST")
	if err == nil {
		t.Fatalf("expected error for mismatched sig, got nil")
	}
	if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
	}
}

func TestVerifyMLDSAKeyAndSigQ_NilQueue_BadSuite(t *testing.T) {
	// Bad suite → verifySig returns err (not ok=false). sigQueue=nil path.
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	fakePubkey := make([]byte, 32)
	fakePubkey[0] = 0xAA
	expectedKeyID := sha3_256(fakePubkey)
	w := WitnessItem{
		SuiteID:   0xFE, // bad suite
		Pubkey:    fakePubkey,
		Signature: make([]byte, 2), // [sighash_type_byte, one_sig_byte]
	}

	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("sighash cache: %v", err)
	}

	err = verifyMLDSAKeyAndSigQ(w, expectedKeyID, tx, inputIndex, inputValue, chainID, cache, nil, nil, "TEST")
	if err == nil {
		t.Fatalf("expected error for bad suite ID, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark: Parallel queue vs sequential verify
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkSigCheckQueue_Flush(b *testing.B) {
	kp := mustMLDSA87KeypairB(b)

	// Pre-generate signatures.
	const n = 16
	type task struct {
		sig    []byte
		digest [32]byte
	}
	tasks := make([]task, n)
	for i := range tasks {
		tasks[i].digest[0] = byte(i)
		var err error
		tasks[i].sig, err = kp.SignDigest32(tasks[i].digest)
		if err != nil {
			b.Fatalf("sign %d: %v", i, err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := NewSigCheckQueue(0)
		for _, t := range tasks {
			q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), t.sig, t.digest, txerr(TX_ERR_SIG_INVALID, "bench"))
		}
		if err := q.Flush(); err != nil {
			b.Fatalf("flush: %v", err)
		}
	}
}

func BenchmarkSigCheckQueue_Sequential(b *testing.B) {
	kp := mustMLDSA87KeypairB(b)

	const n = 16
	type task struct {
		sig    []byte
		digest [32]byte
	}
	tasks := make([]task, n)
	for i := range tasks {
		tasks[i].digest[0] = byte(i)
		var err error
		tasks[i].sig, err = kp.SignDigest32(tasks[i].digest)
		if err != nil {
			b.Fatalf("sign %d: %v", i, err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, t := range tasks {
			ok, err := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), t.sig, t.digest)
			if err != nil {
				b.Fatalf("verify: %v", err)
			}
			if !ok {
				b.Fatalf("verify=false")
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent safety: each goroutine gets its own queue
// ─────────────────────────────────────────────────────────────────────────────

func TestSigCheckQueue_ConcurrentFlushSafety(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var wg sync.WaitGroup
	const goroutines = 8

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			q := NewSigCheckQueue(2)
			for i := 0; i < 4; i++ {
				var d [32]byte
				d[0] = byte(gid)
				d[1] = byte(i)
				sig, err := kp.SignDigest32(d)
				if err != nil {
					t.Errorf("goroutine %d sign %d: %v", gid, i, err)
					return
				}
				q.Push(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, d, txerr(TX_ERR_SIG_INVALID, "concurrent"))
			}
			if err := q.Flush(); err != nil {
				t.Errorf("goroutine %d flush: %v", gid, err)
			}
		}(g)
	}
	wg.Wait()
}

type queueTypedNilError struct{}

func (*queueTypedNilError) Error() string { panic("typed-nil Error must not be called") }

func requiredOrderedKeypair(t *testing.T) *MLDSA87Keypair {
	t.Helper()
	kp, err := NewMLDSA87Keypair()
	if err != nil {
		t.Fatalf("required ML-DSA-87 backend: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func queueVerifierHook(t *testing.T, fn func(string, []byte, []byte, []byte) (bool, error)) {
	t.Helper()
	if err := ensureOpenSSLConsensusInit(); err != nil {
		t.Fatal(err)
	}
	original := opensslVerifySigOneShotFn
	t.Cleanup(func() { opensslVerifySigOneShotFn = original })
	opensslVerifySigOneShotFn = fn
}

func queueFixtureTask(q *SigCheckQueue, index byte, err error) {
	q.Push(0x01, make([]byte, 2592), make([]byte, 4627), [32]byte{index}, err)
}

// queueFixtureTaskEqual compares the comparable error and panic fixtures by identity.
func queueFixtureTaskEqual(got, want sigCheckTask) bool {
	return got.suiteID == want.suiteID &&
		(got.pubkey == nil) == (want.pubkey == nil) && bytes.Equal(got.pubkey, want.pubkey) &&
		(got.sig == nil) == (want.sig == nil) && bytes.Equal(got.sig, want.sig) &&
		got.digest == want.digest && any(got.errOnFail) == any(want.errOnFail) &&
		got.settled == want.settled && any(got.err) == any(want.err) &&
		got.panicValue == want.panicValue && got.panicked == want.panicked
}

func requireQueueCleared(t *testing.T, q *SigCheckQueue, n int) {
	t.Helper()
	if q.Len() != 0 {
		t.Fatalf("consumed queue length=%d", q.Len())
	}
	for i, task := range q.tasks[:n] {
		if !queueFixtureTaskEqual(task, sigCheckTask{}) {
			t.Fatalf("consumed slot %d retains task outcome or payload", i)
		}
	}
}

func requireQueuePanic(t *testing.T, want any, call func()) {
	t.Helper()
	completed := false
	defer func() {
		got := recover()
		if completed || got != want {
			t.Fatalf("raw panic: completed=%v got=%#v want=%#v", completed, got, want)
		}
	}()
	call()
	completed = true
}

func TestSigCheckQueue_OrderedResults(t *testing.T) {
	for _, workers := range []int{-1, 0, 1, 2, 10} {
		for _, n := range []int{2, 5} {
			t.Run(fmt.Sprintf("workers%d/n%d", workers, n), func(t *testing.T) {
				var calls atomic.Int32
				queueVerifierHook(t, func(_ string, _, _, _ []byte) (bool, error) {
					calls.Add(1)
					return false, nil
				})
				q := &SigCheckQueue{workers: workers}
				first := errors.New("first task")
				queueFixtureTask(q, 0, first)
				for i := 1; i < n; i++ {
					queueFixtureTask(q, byte(i), errors.New("later task"))
				}
				if got := q.Flush(); any(got) != any(first) {
					t.Fatalf("lowest submitted error identity lost: %v", got)
				}
				if calls.Load() != int32(n) {
					t.Fatalf("full batch completed %d tasks, want %d", calls.Load(), n)
				}
				requireQueueCleared(t, q, n)
			})
		}
	}
	for _, n := range []int{2, 5} {
		t.Run(fmt.Sprintf("reverse backend completion and join/n%d", n), func(t *testing.T) {
			var lowerEntered, higherDone, releaseLower chan struct{}
			var calls atomic.Int32
			queueVerifierHook(t, func(_ string, _, _, msg []byte) (bool, error) {
				calls.Add(1)
				switch msg[0] {
				case 0:
					close(lowerEntered)
					<-releaseLower
				case 1:
					<-lowerEntered
					close(higherDone)
				}
				return false, nil
			})
			q := NewSigCheckQueue(2)
			first := errors.New("lower")
			queueFixtureTask(q, 0, first)
			for i := 1; i < n; i++ {
				queueFixtureTask(q, byte(i), fmt.Errorf("higher task %d", i))
			}
			synctest.Test(t, func(t *testing.T) {
				lowerEntered, higherDone, releaseLower = make(chan struct{}), make(chan struct{}), make(chan struct{})
				done := make(chan error, 1)
				go func() { done <- q.Flush() }()
				<-higherDone
				synctest.Wait()
				premature := len(done) != 0
				close(releaseLower)
				got := <-done
				synctest.Wait()
				if premature {
					t.Fatal("Flush returned before its lower worker joined")
				}
				if any(got) != any(first) || calls.Load() != int32(n) {
					t.Fatalf("reverse completion selected %v, calls=%d", got, calls.Load())
				}
				requireQueueCleared(t, q, n)
			})
		})
	}
	t.Run("all valid normalization", func(t *testing.T) {
		var calls atomic.Int32
		queueVerifierHook(t, func(string, []byte, []byte, []byte) (bool, error) {
			calls.Add(1)
			return true, nil
		})
		for _, workers := range []int{-1, 0, 1, 2, 10} {
			q := &SigCheckQueue{workers: workers}
			queueFixtureTask(q, 0, nil)
			queueFixtureTask(q, 1, nil)
			if got := q.Flush(); got != nil {
				t.Fatal(got)
			}
		}
		if calls.Load() != 10 {
			t.Fatalf("valid normalization calls=%d", calls.Load())
		}
	})
}

func TestSigCheckQueue_Settlement(t *testing.T) {
	t.Run("ranges and overlapping terminal selection", func(t *testing.T) {
		calls := [3]int{}
		queueVerifierHook(t, func(_ string, _, _, msg []byte) (bool, error) {
			calls[msg[0]]++
			return msg[0] != 1, nil
		})
		q := NewSigCheckQueue(1)
		first := errors.New("original interval failure")
		for i := byte(0); i < 3; i++ {
			queueFixtureTask(q, i, first)
		}
		for _, interval := range [][2]int{{0, 0}, {3, 3}, {0, 1}} {
			if err := q.settleRange(sigCheckQueueMark{interval[0]}, sigCheckQueueMark{interval[1]}); err != nil {
				t.Fatal(err)
			}
		}
		for _, interval := range [][2]int{{1, 2}, {0, 3}, {1, 3}} {
			if err := q.settleRange(sigCheckQueueMark{interval[0]}, sigCheckQueueMark{interval[1]}); any(err) != any(first) {
				t.Fatal("overlapping selection changed original failure")
			}
		}
		if calls != [3]int{1, 1, 0} || q.tasks[2].settled || q.tasks[2].err != nil || q.tasks[2].panicked || q.tasks[2].panicValue != nil || !q.tasks[0].settled || q.tasks[0].err != nil || q.tasks[0].panicked || q.tasks[0].panicValue != nil {
			t.Fatalf("serial prefix/pending shape: calls=%v tasks=%+v", calls, q.tasks)
		}
		if !q.tasks[1].settled || any(q.tasks[1].err) != any(first) || q.tasks[1].panicked || q.tasks[1].panicValue != nil {
			t.Fatal("original-error payload shape")
		}
		if err := q.Flush(); any(err) != any(first) || calls != [3]int{1, 1, 1} {
			t.Fatalf("Flush recomputed terminal task or omitted pending: err=%v calls=%v", err, calls)
		}
		requireQueueCleared(t, q, 3)
	})
	t.Run("all valid interval positions", func(t *testing.T) {
		var calls int
		queueVerifierHook(t, func(string, []byte, []byte, []byte) (bool, error) { calls++; return true, nil })
		q := NewSigCheckQueue(1)
		for i := byte(0); i < 3; i++ {
			queueFixtureTask(q, i, nil)
		}
		for _, interval := range [][2]int{{0, 0}, {0, 1}, {1, 2}, {2, 3}, {3, 3}, {0, 3}} {
			if err := q.settleRange(sigCheckQueueMark{interval[0]}, sigCheckQueueMark{interval[1]}); err != nil {
				t.Fatal(err)
			}
		}
		if calls != 3 || q.Len() != 3 {
			t.Fatalf("retained range calls=%d len=%d", calls, q.Len())
		}
		if err := q.Flush(); err != nil || calls != 3 {
			t.Fatalf("retained success reexecuted: %v calls=%d", err, calls)
		}
		var nilQueue *SigCheckQueue
		if nilQueue.settleRange(sigCheckQueueMark{}, sigCheckQueueMark{}) != nil {
			t.Fatal("nil empty interval")
		}
	})
	t.Run("invalid numeric ranges have no effects", func(t *testing.T) {
		var calls int
		queueVerifierHook(t, func(string, []byte, []byte, []byte) (bool, error) { calls++; return true, nil })
		q := NewSigCheckQueue(1)
		queueFixtureTask(q, 0, nil)
		before := q.tasks[0]
		for _, bounds := range [][2]int{{-1, 0}, {0, -1}, {1, 0}, {0, 2}} {
			requireQueuePanic(t, "invalid signature queue range", func() {
				_ = q.settleRange(sigCheckQueueMark{bounds[0]}, sigCheckQueueMark{bounds[1]})
			})
			if !queueFixtureTaskEqual(q.tasks[0], before) || calls != 0 {
				t.Fatal("invalid range changed task or invoked verifier")
			}
		}
		var nilQueue *SigCheckQueue
		requireQueuePanic(t, "invalid signature queue range", func() { _ = nilQueue.settleRange(sigCheckQueueMark{}, sigCheckQueueMark{1}) })
	})
	t.Run("errOnFail identities", func(t *testing.T) {
		queueVerifierHook(t, func(string, []byte, []byte, []byte) (bool, error) { return false, nil })
		var typedNil *queueTypedNilError
		for _, original := range []error{nil, errors.New("direct"), fmt.Errorf("wrapped: %w", errors.New("cause")), txerrWithCause("TX_ERR_PARSE", "already caused", TxErrorCauseLocalCryptoBackendFault), typedNil} {
			q := NewSigCheckQueue(1)
			queueFixtureTask(q, 0, original)
			got := q.settleRange(sigCheckQueueMark{}, q.mark())
			if original == nil {
				assertTxErrCodeMsg(t, got, "TX_ERR_SIG_INVALID", "signature verification failed (fail-closed default)")
			} else if any(got) != any(original) {
				t.Fatal("errOnFail original interface replaced")
			}
			if any(q.Flush()) != any(got) {
				t.Fatal("terminal errOnFail identity changed during Flush")
			}
		}
	})
	t.Run("raw hook projection and fresh next batch", func(t *testing.T) {
		var typedNil *queueTypedNilError
		for _, rawOK := range []bool{false, true} {
			for _, rawErr := range []error{errors.New("direct"), fmt.Errorf("wrapped: %w", errors.New("cause")), txerrWithCause("TX_ERR_PARSE", "caused", TxErrorCauseLocalCryptoBackendFault), typedNil} {
				var calls int
				queueVerifierHook(t, func(string, []byte, []byte, []byte) (bool, error) { calls++; return rawOK, rawErr })
				q := NewSigCheckQueue(1)
				queueFixtureTask(q, 0, errors.New("distinct fallback"))
				first := q.settleRange(sigCheckQueueMark{}, q.mark())
				mustTxErrorCause(t, first, "TX_ERR_SIG_INVALID", "verify_sig: EVP_DigestVerify internal error", TxErrorCauseLocalCryptoBackendFault)
				if any(first) == any(rawErr) || any(q.settleRange(sigCheckQueueMark{}, q.mark())) != any(first) || any(q.Flush()) != any(first) || calls != 1 {
					t.Fatal("binding projection or fault memoization changed")
				}
				queueFixtureTask(q, 0, nil)
				next := q.Flush()
				mustTxErrorCause(t, next, "TX_ERR_SIG_INVALID", "verify_sig: EVP_DigestVerify internal error", TxErrorCauseLocalCryptoBackendFault)
				if calls != 2 || any(next) == any(first) {
					t.Fatal("fault survived globally into the next batch")
				}
			}
		}
	})
	t.Run("independent init latched identity", func(t *testing.T) {
		registry := DefaultSuiteRegistry()
		pubkey, sig := make([]byte, 2592), make([]byte, 4627)
		t.Cleanup(resetOpenSSLBootstrapStateForTests)
		q := NewSigCheckQueue(1).WithRegistry(registry)
		t.Cleanup(func() { q.rollbackTo(sigCheckQueueMark{}) })
		resetOpenSSLBootstrapStateForTests()
		calls := 0
		opensslConsensusInitFn = func() error { calls++; return errors.New("synthetic consensus init failure") }
		original := ensureOpenSSLConsensusInit()
		mustTxErrorCause(t, original, "TX_ERR_PARSE", "openssl consensus init: synthetic consensus init failure", TxErrorCauseLocalCryptoBackendFault)
		if ok, got := verifySigWithRegistry(0x01, pubkey, sig, [32]byte{}, registry); ok || any(got) != any(original) {
			t.Fatal("producer did not forward independently observed latched error")
		}
		q.Push(0x01, pubkey, sig, [32]byte{}, errors.New("distinct fallback"))
		if got := q.settleRange(sigCheckQueueMark{}, q.mark()); any(got) != any(original) {
			t.Fatal("first selection replaced independent producer identity")
		}
		if any(q.settleRange(sigCheckQueueMark{}, q.mark())) != any(original) || any(q.Flush()) != any(original) || calls != 1 {
			t.Fatal("init-latched identity or invocation count changed")
		}
		requireQueueCleared(t, q, 1)
	})
	t.Run("copy once cleanup reuse and configuration", func(t *testing.T) {
		pubkey, sig, digest := make([]byte, 2592), make([]byte, 4627), [32]byte{7}
		pubkey[0], sig[0] = 3, 5
		wantPub, wantSig := append([]byte(nil), pubkey...), append([]byte(nil), sig...)
		calls := 0
		queueVerifierHook(t, func(_ string, pub, signature, msg []byte) (bool, error) {
			calls++
			if !bytes.Equal(pub, wantPub) || !bytes.Equal(signature, wantSig) || msg[0] != 7 {
				t.Error("Push retained borrowed bytes or digest")
			}
			return true, nil
		})
		registry, cache := DefaultSuiteRegistry(), NewSigCache(8)
		q := NewSigCheckQueue(1).WithRegistry(registry).WithCache(cache)
		q.Push(0x01, pubkey, sig, digest, nil)
		pubkey[0], sig[0], digest[0] = 9, 9, 9
		if q.settleRange(sigCheckQueueMark{}, q.mark()) != nil || q.Flush() != nil || calls != 1 {
			t.Fatal("owned task did not settle once")
		}
		requireQueueCleared(t, q, 1)
		q.Push(0x01, wantPub, wantSig, [32]byte{7}, nil)
		if q.tasks[0].settled || q.tasks[0].err != nil || q.tasks[0].panicked || q.tasks[0].panicValue != nil {
			t.Fatal("reused index inherited a terminal state")
		}
		if q.Flush() != nil || calls != 1 || q.registry != registry || q.cache != cache {
			t.Fatal("positive cache or queue configuration changed")
		}
	})
	t.Run("rollback preserves exact prefix terminal state", func(t *testing.T) {
		for _, state := range []string{"pending", "success", "error", "panic"} {
			for _, dropped := range []string{"error", "panic"} {
				t.Run(state+"/drop_"+dropped, func(t *testing.T) {
					panicValue := &struct{ label string }{"retained panic"}
					healthy := false
					queueVerifierHook(t, func(_ string, _, _, msg []byte) (bool, error) {
						if healthy {
							return true, nil
						}
						outcome := state
						if msg[0] == 1 {
							outcome = dropped
						}
						if outcome == "panic" {
							panic(panicValue)
						}
						return outcome == "success", nil
					})
					q := NewSigCheckQueue(1)
					original := fmt.Errorf("wrapped: %w", errors.New("original"))
					queueFixtureTask(q, 0, original)
					if state == "panic" {
						requireQueuePanic(t, panicValue, func() { _ = q.settleRange(sigCheckQueueMark{}, q.mark()) })
					} else if state != "pending" {
						got := q.settleRange(sigCheckQueueMark{}, q.mark())
						if (state == "success" && got != nil) || (state == "error" && any(got) != any(original)) {
							t.Fatal("prefix terminal state setup")
						}
					}
					prefix, mark := q.tasks[0], q.mark()
					prefix.pubkey = append([]byte(nil), prefix.pubkey...)
					prefix.sig = append([]byte(nil), prefix.sig...)
					queueFixtureTask(q, 1, errors.New("dropped error"))
					if dropped == "panic" {
						requireQueuePanic(t, panicValue, func() { _ = q.settleRange(mark, q.mark()) })
					} else if any(q.settleRange(mark, q.mark())) != any(q.tasks[1].errOnFail) {
						t.Fatal("dropped error identity")
					}
					q.rollbackTo(mark)
					if q.Len() != 1 || !queueFixtureTaskEqual(q.tasks[0], prefix) || any(q.tasks[0].errOnFail) != any(original) || !queueFixtureTaskEqual(q.tasks[:cap(q.tasks)][1], sigCheckTask{}) {
						t.Fatal("rollback changed prefix or retained dropped outcome")
					}
					healthy = true
					queueFixtureTask(q, 2, nil)
					if q.tasks[1].settled || q.tasks[1].err != nil || q.tasks[1].panicked || q.tasks[1].panicValue != nil {
						t.Fatal("reused suffix retained terminal result")
					}
					got := q.Flush()
					if state == "error" && any(got) != any(original) {
						t.Fatal("retained prefix original error changed")
					}
					if state == "panic" {
						assertTxErrCodeMsg(t, got, "TX_ERR_SIG_INVALID", "signature worker panic (fail-closed)")
					} else if state != "error" && got != nil {
						t.Fatal(got)
					}
					requireQueueCleared(t, q, 2)
					queueFixtureTask(q, 3, nil)
					if q.Flush() != nil {
						t.Fatal("same queue invalid after terminal prefix cleanup")
					}
				})
			}
		}
	})
}

func TestSigCheckQueue_PanicDomains(t *testing.T) {
	panicValue := &struct{ label string }{"raw"}
	for _, n := range []int{1, 3} {
		panicIndices := []int{0}
		if n > 1 {
			panicIndices = append(panicIndices, n-1)
		}
		for _, workers := range []int{1, 3} {
			for _, panicIndex := range panicIndices {
				t.Run(fmt.Sprintf("full/n%d/workers%d/panic%d", n, workers, panicIndex), func(t *testing.T) {
					var calls atomic.Int32
					queueVerifierHook(t, func(_ string, _, _, msg []byte) (bool, error) {
						calls.Add(1)
						if int(msg[0]) == panicIndex {
							panic(panicValue)
						}
						return true, nil
					})
					q := NewSigCheckQueue(workers)
					for i := 0; i < n; i++ {
						queueFixtureTask(q, byte(i), nil)
					}
					if n == 1 {
						requireQueuePanic(t, panicValue, func() { _ = q.Flush() })
					} else {
						assertTxErrCodeMsg(t, q.Flush(), "TX_ERR_SIG_INVALID", "signature worker panic (fail-closed)")
					}
					wantPanics := uint64(0)
					if n > 1 {
						wantPanics = 1
					}
					if calls.Load() != int32(n) || q.Panics() != wantPanics {
						t.Fatalf("full completion=%d panics=%d", calls.Load(), q.Panics())
					}
					requireQueueCleared(t, q, n)
					queueFixtureTask(q, byte(panicIndex+1), nil)
					if q.Flush() != nil || q.Panics() != wantPanics {
						t.Fatal("panic contaminated next batch or cumulative count")
					}
				})
			}
		}
	}
	for _, panicFirst := range []bool{false, true} {
		for _, n := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("private/n%d/panicFirst%v", n, panicFirst), func(t *testing.T) {
				calls := 0
				first := errors.New("lower original error")
				queueVerifierHook(t, func(_ string, _, _, msg []byte) (bool, error) {
					calls++
					if (msg[0] == 0) == panicFirst {
						panic(panicValue)
					}
					return false, nil
				})
				q := NewSigCheckQueue(1)
				for i := 0; i < n; i++ {
					queueFixtureTask(q, byte(i), first)
				}
				selectRange := func() { _ = q.settleRange(sigCheckQueueMark{}, q.mark()) }
				if panicFirst {
					requireQueuePanic(t, panicValue, selectRange)
					requireQueuePanic(t, panicValue, selectRange)
					if !q.tasks[0].settled || !q.tasks[0].panicked || q.tasks[0].panicValue != panicValue || q.tasks[0].err != nil {
						t.Fatal("raw-panic terminal shape")
					}
				} else {
					for range 2 {
						if any(q.settleRange(sigCheckQueueMark{}, q.mark())) != any(first) {
							t.Fatal("earlier error lost to later panic")
						}
					}
				}
				if calls != 1 || q.Panics() != 0 || (n > 1 && q.tasks[1].settled) {
					t.Fatalf("serial selection executed later task: calls=%d", calls)
				}
				if n == 1 && panicFirst {
					requireQueuePanic(t, panicValue, func() { _ = q.Flush() })
				} else {
					got := q.Flush()
					if panicFirst {
						assertTxErrCodeMsg(t, got, "TX_ERR_SIG_INVALID", "signature worker panic (fail-closed)")
					} else if any(got) != any(first) {
						t.Fatal("full reduction changed lower original error")
					}
				}
				if calls != n {
					t.Fatalf("remaining pending cardinality changed verification count=%d want=%d", calls, n)
				}
				wantPanics := uint64(0)
				if n > 1 {
					wantPanics = uint64(n - 1)
					if panicFirst {
						wantPanics = 1
					}
				}
				if q.Panics() != wantPanics {
					t.Fatalf("projected panic count=%d want=%d", q.Panics(), wantPanics)
				}
				requireQueueCleared(t, q, n)
			})
		}
	}
	t.Run("original n greater than one with one pending", func(t *testing.T) {
		calls := 0
		queueVerifierHook(t, func(_ string, _, _, msg []byte) (bool, error) {
			calls++
			if msg[0] == 1 {
				panic(panicValue)
			}
			return true, nil
		})
		q := NewSigCheckQueue(1)
		queueFixtureTask(q, 0, nil)
		queueFixtureTask(q, 1, nil)
		if q.settleRange(sigCheckQueueMark{}, sigCheckQueueMark{1}) != nil {
			t.Fatal("successful prefix")
		}
		assertTxErrCodeMsg(t, q.Flush(), "TX_ERR_SIG_INVALID", "signature worker panic (fail-closed)")
		if calls != 2 || q.Panics() != 1 {
			t.Fatal("remaining pending count selected single-task panic policy")
		}
	})
	t.Run("raw nil and rollback terminal references", func(t *testing.T) {
		t.Setenv("GODEBUG", "panicnil=1")
		healthy := false
		queueVerifierHook(t, func(string, []byte, []byte, []byte) (bool, error) {
			if !healthy {
				panic(nil) //nolint:govet // RUB-721: exercise the required raw-nil outcome with panicnil=1.
			}
			return true, nil
		})
		q := NewSigCheckQueue(1)
		queueFixtureTask(q, 0, nil)
		requireQueuePanic(t, nil, func() { _ = q.settleRange(sigCheckQueueMark{}, q.mark()) })
		if !q.tasks[0].panicked || q.tasks[0].err != nil || q.tasks[0].panicValue != nil {
			t.Fatal("raw nil treated as success")
		}
		q.rollbackTo(sigCheckQueueMark{})
		requireQueueCleared(t, q, 1)
		queueFixtureTask(q, 1, nil)
		if q.tasks[0].settled || q.tasks[0].panicked {
			t.Fatal("rollback reused a cached panic")
		}
		healthy = true
		if q.Flush() != nil || q.Panics() != 0 {
			t.Fatal("raw nil panic contaminated valid next use")
		}
		requireQueueCleared(t, q, 1)
	})
	t.Run("cumulative count across full batches", func(t *testing.T) {
		queueVerifierHook(t, func(string, []byte, []byte, []byte) (bool, error) { panic(panicValue) })
		q := NewSigCheckQueue(2)
		for batch := uint64(1); batch <= 2; batch++ {
			queueFixtureTask(q, 0, nil)
			queueFixtureTask(q, 1, nil)
			assertTxErrCodeMsg(t, q.Flush(), "TX_ERR_SIG_INVALID", "signature worker panic (fail-closed)")
			if q.Panics() != 2*batch {
				t.Fatal("multi-task panic count reset or projected twice")
			}
			requireQueueCleared(t, q, 2)
		}
	})
}
