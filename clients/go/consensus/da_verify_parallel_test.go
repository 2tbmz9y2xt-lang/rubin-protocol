package consensus

import (
	"context"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// VerifyDAChunkHashesParallel tests
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyDAChunkHashes_Empty(t *testing.T) {
	if err := VerifyDAChunkHashesParallel(context.Background(), nil, 2); err != nil {
		t.Fatalf("empty tasks: %v", err)
	}
}

func TestVerifyDAChunkHashes_AllValid(t *testing.T) {
	payloads := [][]byte{
		[]byte("chunk-0-payload-data"),
		[]byte("chunk-1-payload-data"),
		[]byte("chunk-2-payload-data"),
	}
	tasks := make([]DAChunkHashTask, len(payloads))
	for i, p := range payloads {
		tasks[i] = DAChunkHashTask{
			TxIndex:   i,
			DaPayload: p,
			Expected:  sha3_256(p),
		}
	}

	err := VerifyDAChunkHashesParallel(context.Background(), tasks, 2)
	if err != nil {
		t.Fatalf("all valid chunks: %v", err)
	}
}

func TestVerifyDAChunkHashes_OneMismatch(t *testing.T) {
	payload := []byte("correct-payload")
	tasks := []DAChunkHashTask{
		{TxIndex: 0, DaPayload: payload, Expected: sha3_256(payload)},
		{TxIndex: 1, DaPayload: payload, Expected: [32]byte{0xFF}}, // wrong hash
	}

	err := VerifyDAChunkHashesParallel(context.Background(), tasks, 2)
	if err == nil {
		t.Fatalf("expected error for hash mismatch")
	}
	if !isTxErrCode(err, BLOCK_ERR_DA_CHUNK_HASH_INVALID) {
		t.Fatalf("expected BLOCK_ERR_DA_CHUNK_HASH_INVALID, got: %v", err)
	}
}

func TestVerifyDAChunkHashes_SingleTask(t *testing.T) {
	payload := []byte("single-chunk")
	tasks := []DAChunkHashTask{
		{TxIndex: 0, DaPayload: payload, Expected: sha3_256(payload)},
	}
	if err := VerifyDAChunkHashesParallel(context.Background(), tasks, 1); err != nil {
		t.Fatalf("single valid chunk: %v", err)
	}
}

func TestVerifyDAChunkHashes_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before running

	payload := []byte("data")
	tasks := []DAChunkHashTask{
		{TxIndex: 0, DaPayload: payload, Expected: sha3_256(payload)},
	}
	err := VerifyDAChunkHashesParallel(ctx, tasks, 1)
	if err == nil {
		t.Fatalf("expected error from cancelled context")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyDAPayloadCommitsParallel tests
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyDAPayloadCommits_Empty(t *testing.T) {
	if err := VerifyDAPayloadCommitsParallel(context.Background(), nil, 2); err != nil {
		t.Fatalf("empty tasks: %v", err)
	}
}

func TestVerifyDAPayloadCommits_SingleValid(t *testing.T) {
	chunks := [][]byte{[]byte("part-a"), []byte("part-b")}
	var concat []byte
	for _, c := range chunks {
		concat = append(concat, c...)
	}
	expected := sha3_256(concat)

	tasks := []DAPayloadCommitTask{{
		DaID:           [32]byte{0x01},
		ChunkCount:     2,
		ChunkPayloads:  chunks,
		ExpectedCommit: expected,
	}}

	if err := VerifyDAPayloadCommitsParallel(context.Background(), tasks, 1); err != nil {
		t.Fatalf("valid commit: %v", err)
	}
}

func TestVerifyDAPayloadCommits_Mismatch(t *testing.T) {
	chunks := [][]byte{[]byte("part-a"), []byte("part-b")}

	tasks := []DAPayloadCommitTask{{
		DaID:           [32]byte{0x01},
		ChunkCount:     2,
		ChunkPayloads:  chunks,
		ExpectedCommit: [32]byte{0xFF}, // wrong
	}}

	err := VerifyDAPayloadCommitsParallel(context.Background(), tasks, 1)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if !isTxErrCode(err, BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID) {
		t.Fatalf("expected BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, got: %v", err)
	}
}

func TestVerifyDAPayloadCommits_MultipleValid(t *testing.T) {
	makeTasks := func() []DAPayloadCommitTask {
		var tasks []DAPayloadCommitTask
		for i := 0; i < 3; i++ {
			chunk := []byte{byte(i), byte(i + 1), byte(i + 2)}
			expected := sha3_256(chunk)
			tasks = append(tasks, DAPayloadCommitTask{
				DaID:           [32]byte{byte(i)},
				ChunkCount:     1,
				ChunkPayloads:  [][]byte{chunk},
				ExpectedCommit: expected,
			})
		}
		return tasks
	}

	if err := VerifyDAPayloadCommitsParallel(context.Background(), makeTasks(), 4); err != nil {
		t.Fatalf("multiple valid: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Collect* tests
// ─────────────────────────────────────────────────────────────────────────────

func TestCollectDAChunkHashTasks_NoDA(t *testing.T) {
	txs := []*Tx{{TxKind: 0x00}} // regular tx
	tasks := CollectDAChunkHashTasks(txs)
	if len(tasks) != 0 {
		t.Fatalf("expected 0 tasks for non-DA block, got %d", len(tasks))
	}
}

func TestCollectDAChunkHashTasks_WithChunks(t *testing.T) {
	payload := []byte("test-chunk-data")
	txs := []*Tx{
		{TxKind: 0x00}, // regular tx
		{TxKind: 0x02, DaChunkCore: &DaChunkCore{
			DaID: [32]byte{0x01}, ChunkIndex: 0, ChunkHash: sha3_256(payload),
		}, DaPayload: payload},
		{TxKind: 0x02, DaChunkCore: &DaChunkCore{
			DaID: [32]byte{0x01}, ChunkIndex: 1, ChunkHash: sha3_256([]byte("other")),
		}, DaPayload: []byte("other")},
	}

	tasks := CollectDAChunkHashTasks(txs)
	if len(tasks) != 2 {
		t.Fatalf("expected 2 chunk tasks, got %d", len(tasks))
	}
	if tasks[0].TxIndex != 1 || tasks[1].TxIndex != 2 {
		t.Fatalf("wrong tx indices: %d, %d", tasks[0].TxIndex, tasks[1].TxIndex)
	}
}

func TestCollectDAPayloadCommitTasks_Empty(t *testing.T) {
	tasks := CollectDAPayloadCommitTasks([]*Tx{{TxKind: 0x00}})
	if tasks != nil {
		t.Fatalf("expected nil for no DA commits, got %d tasks", len(tasks))
	}
}

func TestCollectDAPayloadCommitTasks_WithCommitAndChunks(t *testing.T) {
	daID := [32]byte{0xAA}
	chunk0 := []byte("chunk-zero")
	chunk1 := []byte("chunk-one")
	concat := append(append([]byte(nil), chunk0...), chunk1...)
	commitment := sha3_256(concat)

	txs := []*Tx{
		{TxKind: 0x01, DaCommitCore: &DaCommitCore{
			DaID: daID, ChunkCount: 2,
		}, Outputs: []TxOutput{{
			CovenantType: COV_TYPE_DA_COMMIT,
			CovenantData: commitment[:],
		}}},
		{TxKind: 0x02, DaChunkCore: &DaChunkCore{
			DaID: daID, ChunkIndex: 0, ChunkHash: sha3_256(chunk0),
		}, DaPayload: chunk0},
		{TxKind: 0x02, DaChunkCore: &DaChunkCore{
			DaID: daID, ChunkIndex: 1, ChunkHash: sha3_256(chunk1),
		}, DaPayload: chunk1},
	}

	tasks := CollectDAPayloadCommitTasks(txs)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 commit task, got %d", len(tasks))
	}
	if tasks[0].ChunkCount != 2 {
		t.Fatalf("expected 2 chunks, got %d", tasks[0].ChunkCount)
	}
	if tasks[0].ExpectedCommit != commitment {
		t.Fatalf("commitment mismatch")
	}
}

func TestCollectDAChunkHashTasks_NilChunkCore(t *testing.T) {
	// tx_kind=0x02 but DaChunkCore is nil → should be skipped.
	txs := []*Tx{{TxKind: 0x02, DaChunkCore: nil}}
	tasks := CollectDAChunkHashTasks(txs)
	if len(tasks) != 0 {
		t.Fatalf("expected 0 tasks for nil DaChunkCore, got %d", len(tasks))
	}
}

func TestCollectDAPayloadCommitTasks_NilCommitCore(t *testing.T) {
	// tx_kind=0x01 but DaCommitCore is nil → should be skipped.
	txs := []*Tx{{TxKind: 0x01, DaCommitCore: nil}}
	tasks := CollectDAPayloadCommitTasks(txs)
	if tasks != nil {
		t.Fatalf("expected nil for nil DaCommitCore, got %d tasks", len(tasks))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end: collect + verify
// ─────────────────────────────────────────────────────────────────────────────

func TestDAParallel_EndToEnd_Valid(t *testing.T) {
	daID := [32]byte{0xBB}
	chunk0 := []byte("e2e-chunk-0")
	chunk1 := []byte("e2e-chunk-1")
	concat := append(append([]byte(nil), chunk0...), chunk1...)
	commitment := sha3_256(concat)

	txs := []*Tx{
		{TxKind: 0x01, DaCommitCore: &DaCommitCore{
			DaID: daID, ChunkCount: 2,
		}, Outputs: []TxOutput{{
			CovenantType: COV_TYPE_DA_COMMIT,
			CovenantData: commitment[:],
		}}},
		{TxKind: 0x02, DaChunkCore: &DaChunkCore{
			DaID: daID, ChunkIndex: 0, ChunkHash: sha3_256(chunk0),
		}, DaPayload: chunk0},
		{TxKind: 0x02, DaChunkCore: &DaChunkCore{
			DaID: daID, ChunkIndex: 1, ChunkHash: sha3_256(chunk1),
		}, DaPayload: chunk1},
	}

	ctx := context.Background()

	// Phase 1: parallel chunk hash verification.
	chunkTasks := CollectDAChunkHashTasks(txs)
	if err := VerifyDAChunkHashesParallel(ctx, chunkTasks, 2); err != nil {
		t.Fatalf("chunk hash verification: %v", err)
	}

	// Phase 2: parallel payload commitment verification.
	commitTasks := CollectDAPayloadCommitTasks(txs)
	if err := VerifyDAPayloadCommitsParallel(ctx, commitTasks, 2); err != nil {
		t.Fatalf("payload commit verification: %v", err)
	}
}

func TestDAParallel_EndToEnd_BadChunkHash(t *testing.T) {
	daID := [32]byte{0xCC}
	chunk0 := []byte("bad-hash-chunk")

	commitHash := sha3_256(chunk0)
	txs := []*Tx{
		{TxKind: 0x01, DaCommitCore: &DaCommitCore{
			DaID: daID, ChunkCount: 1,
		}, Outputs: []TxOutput{{
			CovenantType: COV_TYPE_DA_COMMIT,
			CovenantData: commitHash[:],
		}}},
		{TxKind: 0x02, DaChunkCore: &DaChunkCore{
			DaID: daID, ChunkIndex: 0, ChunkHash: [32]byte{0xFF}, // wrong
		}, DaPayload: chunk0},
	}

	chunkTasks := CollectDAChunkHashTasks(txs)
	err := VerifyDAChunkHashesParallel(context.Background(), chunkTasks, 1)
	if err == nil {
		t.Fatalf("expected chunk hash error")
	}
	if !isTxErrCode(err, BLOCK_ERR_DA_CHUNK_HASH_INVALID) {
		t.Fatalf("expected BLOCK_ERR_DA_CHUNK_HASH_INVALID, got: %v", err)
	}
}
