package consensus

import (
	"context"
)

// DAChunkHashTask describes a single chunk hash verification job.
type DAChunkHashTask struct {
	TxIndex   int      // position of the chunk tx in the block (for error ordering)
	DaPayload []byte   // raw chunk payload
	Expected  [32]byte // expected SHA3-256 hash from DaChunkCore.ChunkHash
}

// VerifyDAChunkHashesParallel verifies all DA chunk hashes in parallel using
// a bounded worker pool. Returns the first error by tx index (deterministic).
//
// This extracts the CPU-heavy SHA3-256 hashing from the sequential
// validateDASetIntegrity path, allowing chunk hashes to be computed
// concurrently while the structural checks remain sequential.
func VerifyDAChunkHashesParallel(ctx context.Context, tasks []DAChunkHashTask, workers int) error {
	if len(tasks) == 0 {
		return nil
	}

	results := RunFunc[DAChunkHashTask, struct{}](
		ctx,
		workers,
		tasks,
		func(_ context.Context, t DAChunkHashTask) (struct{}, error) {
			got := sha3_256(t.DaPayload)
			if got != t.Expected {
				return struct{}{}, txerr(BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch")
			}
			return struct{}{}, nil
		},
	)

	return FirstError(results)
}

// DAPayloadCommitTask describes a single payload commitment verification job.
// Each task represents one complete DA set (commit + all chunks).
type DAPayloadCommitTask struct {
	DaID           [32]byte
	ChunkCount     uint16
	ChunkPayloads  [][]byte // ordered by chunk index [0..ChunkCount-1]
	ExpectedCommit [32]byte // expected SHA3-256 of concatenated payloads
}

// VerifyDAPayloadCommitsParallel verifies all DA payload commitments in
// parallel. Each task concatenates its chunks' payloads and computes
// SHA3-256, comparing against the commitment in the DA commit output.
//
// Returns the first error by task index (deterministic, sorted by DA ID).
func VerifyDAPayloadCommitsParallel(ctx context.Context, tasks []DAPayloadCommitTask, workers int) error {
	if len(tasks) == 0 {
		return nil
	}

	results := RunFunc[DAPayloadCommitTask, struct{}](
		ctx,
		workers,
		tasks,
		func(_ context.Context, t DAPayloadCommitTask) (struct{}, error) {
			var concat []byte
			for _, p := range t.ChunkPayloads {
				concat = append(concat, p...)
			}
			got := sha3_256(concat)
			if got != t.ExpectedCommit {
				return struct{}{}, txerr(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "payload commitment mismatch")
			}
			return struct{}{}, nil
		},
	)

	return FirstError(results)
}

// CollectDAChunkHashTasks scans block transactions and collects all DA chunk
// hash verification tasks. Returns nil if no DA chunks are present.
func CollectDAChunkHashTasks(txs []*Tx) []DAChunkHashTask {
	var tasks []DAChunkHashTask
	for i, tx := range txs {
		if tx.TxKind != 0x02 || tx.DaChunkCore == nil {
			continue
		}
		tasks = append(tasks, DAChunkHashTask{
			TxIndex:   i,
			DaPayload: tx.DaPayload,
			Expected:  tx.DaChunkCore.ChunkHash,
		})
	}
	return tasks
}

// CollectDAPayloadCommitTasks scans block transactions and collects payload
// commitment verification tasks. Each task groups all chunks for a single
// DA ID. Tasks are returned in deterministic order (sorted by DA ID).
//
// Precondition: the caller has already enforced DA-set structural integrity
// for every collected DA ID:
//  1. no duplicate chunk index exists for the DA ID,
//  2. len(chunks) == chunkCount for the DA commit,
//  3. every chunk index in [0, chunkCount-1] is present.
//
// Snapshot import, fast-sync, or any other caller that bypasses the
// sequential validateDASetIntegrity phase MUST re-enforce this contiguity
// contract independently before calling this helper.
func CollectDAPayloadCommitTasks(txs []*Tx) []DAPayloadCommitTask {
	commits := make(map[[32]byte]*Tx)
	chunks := make(map[[32]byte]map[uint16]*Tx)

	for _, tx := range txs {
		switch tx.TxKind {
		case 0x01:
			if tx.DaCommitCore == nil {
				continue
			}
			commits[tx.DaCommitCore.DaID] = tx
		case 0x02:
			if tx.DaChunkCore == nil {
				continue
			}
			daID := tx.DaChunkCore.DaID
			if chunks[daID] == nil {
				chunks[daID] = make(map[uint16]*Tx)
			}
			chunks[daID][tx.DaChunkCore.ChunkIndex] = tx
		}
	}

	if len(commits) == 0 {
		return nil
	}

	ids := sortedDAIDs(commits)
	tasks := make([]DAPayloadCommitTask, 0, len(ids))

	for _, daID := range ids {
		commitTx := commits[daID]
		chunkCount := commitTx.DaCommitCore.ChunkCount
		chunkSet := chunks[daID]

		payloads := make([][]byte, chunkCount)
		for i := uint16(0); i < chunkCount; i++ {
			if chunkTx, ok := chunkSet[i]; ok {
				payloads[i] = chunkTx.DaPayload
			}
		}

		// Extract expected commitment from DA_COMMIT output.
		var expectedCommit [32]byte
		for _, out := range commitTx.Outputs {
			if out.CovenantType == COV_TYPE_DA_COMMIT && len(out.CovenantData) == 32 {
				copy(expectedCommit[:], out.CovenantData)
				break
			}
		}

		tasks = append(tasks, DAPayloadCommitTask{
			DaID:           daID,
			ChunkCount:     chunkCount,
			ChunkPayloads:  payloads,
			ExpectedCommit: expectedCommit,
		})
	}

	return tasks
}
