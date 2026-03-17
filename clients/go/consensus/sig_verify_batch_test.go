package consensus

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
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
// VerifySignaturesBatch unit tests
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifySignaturesBatch_AllValid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var tasks []SigVerifyRequest
	for i := 0; i < 4; i++ {
		var d [32]byte
		d[0] = byte(i)
		sig, err := kp.SignDigest32(d)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		tasks = append(tasks, SigVerifyRequest{
			SuiteID: SUITE_ID_ML_DSA_87,
			Pubkey:  kp.PubkeyBytes(),
			Sig:     sig,
			Digest:  d,
		})
	}
	results := VerifySignaturesBatch(tasks, 2)
	for i, err := range results {
		if err != nil {
			t.Fatalf("task %d: unexpected error: %v", i, err)
		}
	}
}

func TestVerifySignaturesBatch_MixedValidity(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var tasks []SigVerifyRequest
	for i := 0; i < 4; i++ {
		var d [32]byte
		d[0] = byte(i)
		sig, err := kp.SignDigest32(d)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		// Corrupt task 1 and 3.
		if i == 1 || i == 3 {
			d[1] ^= 0xFF
		}
		tasks = append(tasks, SigVerifyRequest{
			SuiteID: SUITE_ID_ML_DSA_87,
			Pubkey:  kp.PubkeyBytes(),
			Sig:     sig,
			Digest:  d,
		})
	}
	results := VerifySignaturesBatch(tasks, 4)
	if results[0] != nil {
		t.Fatalf("task 0 should be valid, got: %v", results[0])
	}
	if results[1] == nil {
		t.Fatalf("task 1 should be invalid")
	}
	if results[2] != nil {
		t.Fatalf("task 2 should be valid, got: %v", results[2])
	}
	if results[3] == nil {
		t.Fatalf("task 3 should be invalid")
	}
}

func TestVerifySignaturesBatch_Empty(t *testing.T) {
	results := VerifySignaturesBatch(nil, 4)
	if results != nil {
		t.Fatalf("expected nil for empty input, got %v", results)
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

// ─────────────────────────────────────────────────────────────────────────────
// VerifySignaturesBatch: single-task fast path and default-workers coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifySignaturesBatch_SingleValid_DefaultWorkers(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var d [32]byte
	d[0] = 0xAA
	sig, err := kp.SignDigest32(d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// workers=0 → defaults to GOMAXPROCS, then clamped to len(tasks)=1.
	// Exercises: lines 181-183 (default workers), 184-186 (clamp), 190-191 (single fast path), 197 (return).
	results := VerifySignaturesBatch([]SigVerifyRequest{{
		SuiteID: SUITE_ID_ML_DSA_87,
		Pubkey:  kp.PubkeyBytes(),
		Sig:     sig,
		Digest:  d,
	}}, 0)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0] != nil {
		t.Fatalf("expected nil error for valid sig, got: %v", results[0])
	}
}

func TestVerifySignaturesBatch_SingleInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var d [32]byte
	d[0] = 0xBB
	sig, err := kp.SignDigest32(d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	d[0] ^= 0xFF // corrupt digest → verifySig returns ok=false
	// Exercises: lines 194-196 (!ok branch in single-task path).
	results := VerifySignaturesBatch([]SigVerifyRequest{{
		SuiteID: SUITE_ID_ML_DSA_87,
		Pubkey:  kp.PubkeyBytes(),
		Sig:     sig,
		Digest:  d,
	}}, 1)
	if results[0] == nil {
		t.Fatalf("expected error for invalid sig")
	}
	if !isTxErrCode(results[0], TX_ERR_SIG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", results[0])
	}
}

func TestVerifySignaturesBatch_SingleBadSuiteError(t *testing.T) {
	// Bad suite ID → verifySig returns err (not ok=false).
	// Exercises: lines 192-193 (err != nil branch in single-task path).
	results := VerifySignaturesBatch([]SigVerifyRequest{{
		SuiteID: 0xFE,
		Pubkey:  []byte("fake"),
		Sig:     []byte("fake"),
		Digest:  [32]byte{},
	}}, 1)
	if results[0] == nil {
		t.Fatalf("expected error for bad suite ID")
	}
}

func TestSigCheckQueue_Multi_BadSuiteError(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	// 1 worker: deterministic sequential processing inside goroutine.
	// Task 0 triggers verifySig error (bad suite) → anyFailed=true.
	// Task 1 hits anyFailed.Load() → continue (drain path).
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

func TestVerifySignaturesBatch_Multi_BadSuiteError(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var d [32]byte
	d[0] = 0xCC
	sig, err := kp.SignDigest32(d)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Task 0 has bad suite → verifySig returns err (not ok=false).
	// Exercises the multi-goroutine err!=nil branch (line 233-235).
	tasks := []SigVerifyRequest{
		{SuiteID: 0xFE, Pubkey: []byte("fake"), Sig: []byte("fake"), Digest: [32]byte{}},
		{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp.PubkeyBytes(), Sig: sig, Digest: d},
	}
	results := VerifySignaturesBatch(tasks, 1)
	if results[0] == nil {
		t.Fatalf("expected error for bad suite ID in multi-task batch")
	}
	// Task 1 should be valid.
	if results[1] != nil {
		t.Fatalf("expected valid sig for task 1, got: %v", results[1])
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
