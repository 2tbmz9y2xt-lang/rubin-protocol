use std::collections::{BTreeMap, HashMap};

use crate::constants::{
    COV_TYPE_DA_COMMIT, MAX_DA_BATCHES_PER_BLOCK, MAX_DA_BYTES_PER_BLOCK, MAX_DA_CHUNK_COUNT,
};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::tx::Tx;
use crate::worker_pool::{
    run_worker_pool, WorkerCancellationToken, WorkerPoolError, WorkerPoolRunError, WorkerResult,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaChunkHashTask {
    pub tx_index: usize,
    pub da_payload: Vec<u8>,
    pub expected: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaPayloadCommitTask {
    pub da_id: [u8; 32],
    pub chunk_count: u16,
    pub chunk_payloads: Vec<Vec<u8>>,
    pub expected_commit: [u8; 32],
}

/// Verify DA chunk hashes in bounded parallel workers and reduce the first
/// error by submission order, which must already match block tx order.
pub fn verify_da_chunk_hashes_parallel(
    tasks: Vec<DaChunkHashTask>,
    workers: usize,
) -> Result<(), TxError> {
    if tasks.is_empty() {
        return Ok(());
    }

    let token = WorkerCancellationToken::new();
    let max_tasks = tasks.len();
    let results = run_worker_pool(&token, workers, max_tasks, tasks, |_cancel, task| {
        let got = sha3_256(&task.da_payload);
        if got != task.expected {
            return Err(TxError::new(
                ErrorCode::BlockErrDaChunkHashInvalid,
                "chunk_hash mismatch",
            ));
        }
        Ok(())
    })
    .map_err(da_run_error_to_tx_error)?;

    reduce_da_results(results, ErrorCode::BlockErrDaSetInvalid)
}

pub fn verify_da_payload_commits_parallel(
    tasks: Vec<DaPayloadCommitTask>,
    workers: usize,
) -> Result<(), TxError> {
    if tasks.is_empty() {
        return Ok(());
    }

    let token = WorkerCancellationToken::new();
    let max_tasks = tasks.len();
    let results = run_worker_pool(&token, workers, max_tasks, tasks, |_cancel, task| {
        let total_len = total_payload_len(task.chunk_payloads.iter().map(Vec::len))?;
        if total_len as u64 > MAX_DA_BYTES_PER_BLOCK {
            return Err(TxError::new(
                ErrorCode::BlockErrDaBatchExceeded,
                "DA payload batch exceeds block cap",
            ));
        }
        let mut concat = Vec::with_capacity(total_len);
        for payload in task.chunk_payloads {
            concat.extend_from_slice(&payload);
        }
        let got = sha3_256(&concat);
        if got != task.expected_commit {
            return Err(TxError::new(
                ErrorCode::BlockErrDaPayloadCommitInvalid,
                "payload commitment mismatch",
            ));
        }
        Ok(())
    })
    .map_err(da_run_error_to_tx_error)?;

    reduce_da_results(results, ErrorCode::BlockErrDaSetInvalid)
}

/// Collect DA chunk-hash verification tasks in the same order as block txs.
pub fn collect_da_chunk_hash_tasks(txs: &[Tx]) -> Vec<DaChunkHashTask> {
    let mut tasks = Vec::new();
    for (tx_index, tx) in txs.iter().enumerate() {
        if tx.tx_kind != 0x02 {
            continue;
        }
        let Some(core) = tx.da_chunk_core.as_ref() else {
            continue;
        };
        tasks.push(DaChunkHashTask {
            tx_index,
            da_payload: tx.da_payload.clone(),
            expected: core.chunk_hash,
        });
    }
    tasks
}

/// Collect payload-commit verification tasks in deterministic DA-ID order.
///
/// Unlike the Go helper, this helper re-checks the DA-set structural envelope so
/// helper-only callers fail closed instead of silently inheriting missing
/// `validate_block_basic` preconditions.
pub fn collect_da_payload_commit_tasks(txs: &[Tx]) -> Result<Vec<DaPayloadCommitTask>, TxError> {
    let mut commits: BTreeMap<[u8; 32], &Tx> = BTreeMap::new();
    let mut chunks: BTreeMap<[u8; 32], HashMap<u16, &Tx>> = BTreeMap::new();
    let mut total_da_payload_bytes: u64 = 0;

    for tx in txs {
        match tx.tx_kind {
            0x01 => {
                let Some(core) = tx.da_commit_core.as_ref() else {
                    continue;
                };
                if commits.insert(core.da_id, tx).is_some() {
                    return Err(TxError::new(
                        ErrorCode::BlockErrDaSetInvalid,
                        "duplicate DA commit for da_id",
                    ));
                }
            }
            0x02 => {
                let Some(core) = tx.da_chunk_core.as_ref() else {
                    continue;
                };
                total_da_payload_bytes = total_da_payload_bytes
                    .checked_add(tx.da_payload.len() as u64)
                    .ok_or_else(|| {
                        TxError::new(
                            ErrorCode::BlockErrDaBatchExceeded,
                            "DA payload bytes overflow",
                        )
                    })?;
                if total_da_payload_bytes > MAX_DA_BYTES_PER_BLOCK {
                    return Err(TxError::new(
                        ErrorCode::BlockErrDaBatchExceeded,
                        "DA payload batch exceeds block cap",
                    ));
                }
                chunks.entry(core.da_id).or_default();
                if chunks
                    .get_mut(&core.da_id)
                    .expect("entry inserted")
                    .insert(core.chunk_index, tx)
                    .is_some()
                {
                    return Err(TxError::new(
                        ErrorCode::BlockErrDaSetInvalid,
                        "duplicate DA chunk index",
                    ));
                }
            }
            _ => {}
        }
    }

    if commits.is_empty() {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }
        return Err(TxError::new(
            ErrorCode::BlockErrDaSetInvalid,
            "DA chunks without DA commit",
        ));
    }

    if commits.len() > MAX_DA_BATCHES_PER_BLOCK as usize {
        return Err(TxError::new(
            ErrorCode::BlockErrDaBatchExceeded,
            "too many DA commits in block",
        ));
    }

    let mut tasks = Vec::with_capacity(commits.len());
    for (da_id, commit_tx) in &commits {
        let commit_core = commit_tx
            .da_commit_core
            .as_ref()
            .expect("commit map stores only DA commit txs");
        let chunk_count = commit_core.chunk_count;
        if chunk_count == 0 || u64::from(chunk_count) > MAX_DA_CHUNK_COUNT {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "chunk_count out of range for tx_kind=0x01",
            ));
        }
        let chunk_set = chunks.get(da_id).ok_or_else(|| {
            TxError::new(ErrorCode::BlockErrDaIncomplete, "DA commit without chunks")
        })?;
        if chunk_set.len() != chunk_count as usize {
            return Err(TxError::new(
                ErrorCode::BlockErrDaIncomplete,
                "DA chunk count mismatch",
            ));
        }

        let mut chunk_payloads = Vec::with_capacity(chunk_count as usize);
        for chunk_index in 0..chunk_count {
            let payload = chunk_set.get(&chunk_index).ok_or_else(|| {
                TxError::new(ErrorCode::BlockErrDaIncomplete, "missing DA chunk index")
            })?;
            chunk_payloads.push(payload.da_payload.clone());
        }

        let mut expected_commit = [0u8; 32];
        let mut da_commit_outputs: u32 = 0;
        for output in &commit_tx.outputs {
            if output.covenant_type != COV_TYPE_DA_COMMIT {
                continue;
            }
            da_commit_outputs += 1;
            if output.covenant_data.len() == 32 {
                expected_commit.copy_from_slice(&output.covenant_data);
            }
        }
        if da_commit_outputs != 1 {
            return Err(TxError::new(
                ErrorCode::BlockErrDaPayloadCommitInvalid,
                "DA commitment output missing or duplicated",
            ));
        }

        tasks.push(DaPayloadCommitTask {
            da_id: *da_id,
            chunk_count,
            chunk_payloads,
            expected_commit,
        });
    }

    Ok(tasks)
}

fn reduce_da_results(
    results: Vec<WorkerResult<(), TxError>>,
    infra_code: ErrorCode,
) -> Result<(), TxError> {
    for result in results {
        match result.error {
            Some(WorkerPoolError::Task(err)) => return Err(err),
            Some(WorkerPoolError::Cancelled) => {
                return Err(TxError::new(
                    infra_code,
                    "DA verification worker canceled (fail-closed)",
                ));
            }
            Some(WorkerPoolError::Panic(_)) => {
                return Err(TxError::new(
                    infra_code,
                    "DA verification worker panic (fail-closed)",
                ));
            }
            None => {}
        }
    }
    Ok(())
}

fn total_payload_len<I>(lengths: I) -> Result<usize, TxError>
where
    I: IntoIterator<Item = usize>,
{
    lengths
        .into_iter()
        .try_fold(0usize, |acc, len| acc.checked_add(len))
        .ok_or_else(|| {
            TxError::new(
                ErrorCode::BlockErrDaPayloadCommitInvalid,
                "payload commitment concat overflow",
            )
        })
}

fn da_run_error_to_tx_error(err: WorkerPoolRunError) -> TxError {
    match err {
        WorkerPoolRunError::InvalidMaxTasks => TxError::new(
            ErrorCode::BlockErrDaSetInvalid,
            "DA verification worker pool misconfigured",
        ),
        WorkerPoolRunError::TooManyTasks { .. } => TxError::new(
            ErrorCode::BlockErrDaBatchExceeded,
            "DA verification task budget exceeded",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        collect_da_chunk_hash_tasks, collect_da_payload_commit_tasks, da_run_error_to_tx_error,
        reduce_da_results, total_payload_len, verify_da_chunk_hashes_parallel,
        verify_da_payload_commits_parallel, DaChunkHashTask, DaPayloadCommitTask,
    };
    use crate::constants::{COV_TYPE_DA_COMMIT, MAX_DA_BYTES_PER_BLOCK};
    use crate::error::{ErrorCode, TxError};
    use crate::tx::Tx;
    use crate::worker_pool::{WorkerPoolError, WorkerPoolRunError, WorkerResult};

    fn empty_tx() -> Tx {
        Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        }
    }

    #[test]
    fn verify_da_chunk_hashes_parallel_empty_is_ok() {
        verify_da_chunk_hashes_parallel(Vec::new(), 4).expect("empty queue");
    }

    #[test]
    fn verify_da_payload_commits_parallel_empty_is_ok() {
        verify_da_payload_commits_parallel(Vec::new(), 4).expect("empty queue");
    }

    #[test]
    fn verify_da_payload_commits_parallel_rejects_payloads_above_block_cap() {
        let err = verify_da_payload_commits_parallel(
            vec![DaPayloadCommitTask {
                da_id: [0x44; 32],
                chunk_count: 1,
                chunk_payloads: vec![vec![0u8; (MAX_DA_BYTES_PER_BLOCK as usize) + 1]],
                expected_commit: [0u8; 32],
            }],
            1,
        )
        .expect_err("oversized payload");
        assert_eq!(err.code, ErrorCode::BlockErrDaBatchExceeded);
    }

    #[test]
    fn collect_da_helpers_skip_malformed_da_core_records() {
        let mut bad_chunk = empty_tx();
        bad_chunk.tx_kind = 0x02;
        bad_chunk.da_payload = vec![0x11, 0x22];

        let mut bad_commit = empty_tx();
        bad_commit.tx_kind = 0x01;

        assert!(collect_da_chunk_hash_tasks(&[bad_chunk]).is_empty());
        assert!(collect_da_payload_commit_tasks(&[bad_commit])
            .expect("skip malformed commit core")
            .is_empty());

        let mixed = vec![
            empty_tx(),
            {
                let mut tx = empty_tx();
                tx.tx_kind = 0x02;
                tx
            },
            {
                let mut tx = empty_tx();
                tx.tx_kind = 0x01;
                tx
            },
        ];
        assert!(collect_da_payload_commit_tasks(&mixed)
            .expect("skip malformed mixed records")
            .is_empty());
    }

    #[test]
    fn collect_da_payload_commit_tasks_rejects_duplicate_commits() {
        let mut first = empty_tx();
        first.tx_kind = 0x01;
        first.da_commit_core = Some(crate::tx::DaCommitCore {
            da_id: [0x11; 32],
            chunk_count: 1,
            retl_domain_id: [0u8; 32],
            batch_number: 0,
            tx_data_root: [0u8; 32],
            state_root: [0u8; 32],
            withdrawals_root: [0u8; 32],
            batch_sig_suite: 0,
            batch_sig: Vec::new(),
        });
        let second = first.clone();

        let err = collect_da_payload_commit_tasks(&[first, second]).expect_err("duplicate commit");
        assert_eq!(err.code, ErrorCode::BlockErrDaSetInvalid);
    }

    #[test]
    fn collect_da_payload_commit_tasks_rejects_chunks_without_commit() {
        let mut chunk = empty_tx();
        chunk.tx_kind = 0x02;
        chunk.da_chunk_core = Some(crate::tx::DaChunkCore {
            da_id: [0x22; 32],
            chunk_index: 0,
            chunk_hash: [0u8; 32],
        });
        chunk.da_payload = vec![0x42];

        let err = collect_da_payload_commit_tasks(&[chunk]).expect_err("missing commit");
        assert_eq!(err.code, ErrorCode::BlockErrDaSetInvalid);
    }

    #[test]
    fn collect_da_payload_commit_tasks_rejects_duplicate_chunk_indices() {
        let da_id = [0x23; 32];
        let mut first = empty_tx();
        first.tx_kind = 0x02;
        first.da_chunk_core = Some(crate::tx::DaChunkCore {
            da_id,
            chunk_index: 0,
            chunk_hash: [0u8; 32],
        });
        first.da_payload = vec![0x01];
        let second = first.clone();
        let mut commit = empty_tx();
        commit.tx_kind = 0x01;
        commit.da_commit_core = Some(crate::tx::DaCommitCore {
            da_id,
            chunk_count: 1,
            retl_domain_id: [0u8; 32],
            batch_number: 0,
            tx_data_root: [0u8; 32],
            state_root: [0u8; 32],
            withdrawals_root: [0u8; 32],
            batch_sig_suite: 0,
            batch_sig: Vec::new(),
        });
        commit.outputs.push(crate::tx::TxOutput {
            value: 0,
            covenant_type: COV_TYPE_DA_COMMIT,
            covenant_data: vec![0u8; 32],
        });

        let err = collect_da_payload_commit_tasks(&[commit, first, second])
            .expect_err("duplicate chunk index");
        assert_eq!(err.code, ErrorCode::BlockErrDaSetInvalid);
    }

    #[test]
    fn collect_da_payload_commit_tasks_rejects_missing_chunk_index() {
        let da_id = [0x33; 32];
        let mut commit = empty_tx();
        commit.tx_kind = 0x01;
        commit.da_commit_core = Some(crate::tx::DaCommitCore {
            da_id,
            chunk_count: 2,
            retl_domain_id: [0u8; 32],
            batch_number: 0,
            tx_data_root: [0u8; 32],
            state_root: [0u8; 32],
            withdrawals_root: [0u8; 32],
            batch_sig_suite: 0,
            batch_sig: Vec::new(),
        });
        commit.outputs.push(crate::tx::TxOutput {
            value: 0,
            covenant_type: COV_TYPE_DA_COMMIT,
            covenant_data: vec![0u8; 32],
        });
        let mut chunk = empty_tx();
        chunk.tx_kind = 0x02;
        chunk.da_chunk_core = Some(crate::tx::DaChunkCore {
            da_id,
            chunk_index: 1,
            chunk_hash: [0u8; 32],
        });
        chunk.da_payload = vec![0x24];

        let err =
            collect_da_payload_commit_tasks(&[commit, chunk]).expect_err("missing chunk index 0");
        assert_eq!(err.code, ErrorCode::BlockErrDaIncomplete);
    }

    #[test]
    fn collect_da_payload_commit_tasks_rejects_duplicate_da_commit_outputs() {
        let da_id = [0x44; 32];
        let mut commit = empty_tx();
        commit.tx_kind = 0x01;
        commit.da_commit_core = Some(crate::tx::DaCommitCore {
            da_id,
            chunk_count: 1,
            retl_domain_id: [0u8; 32],
            batch_number: 0,
            tx_data_root: [0u8; 32],
            state_root: [0u8; 32],
            withdrawals_root: [0u8; 32],
            batch_sig_suite: 0,
            batch_sig: Vec::new(),
        });
        commit.outputs.push(crate::tx::TxOutput {
            value: 0,
            covenant_type: COV_TYPE_DA_COMMIT,
            covenant_data: vec![0u8; 32],
        });
        commit.outputs.push(crate::tx::TxOutput {
            value: 0,
            covenant_type: COV_TYPE_DA_COMMIT,
            covenant_data: vec![1u8; 32],
        });
        let mut chunk = empty_tx();
        chunk.tx_kind = 0x02;
        chunk.da_chunk_core = Some(crate::tx::DaChunkCore {
            da_id,
            chunk_index: 0,
            chunk_hash: [0u8; 32],
        });
        chunk.da_payload = vec![0x99];

        let err = collect_da_payload_commit_tasks(&[commit, chunk])
            .expect_err("duplicate da_commit outputs");
        assert_eq!(err.code, ErrorCode::BlockErrDaPayloadCommitInvalid);
    }

    #[test]
    fn total_payload_len_overflow_fails_closed() {
        let err = total_payload_len([usize::MAX, 1]).expect_err("overflow");
        assert_eq!(err.code, ErrorCode::BlockErrDaPayloadCommitInvalid);
    }

    #[test]
    fn reduce_da_results_maps_cancelled_and_panic_fail_closed() {
        let cancelled = reduce_da_results(
            vec![WorkerResult {
                value: None,
                error: Some(WorkerPoolError::Cancelled),
            }],
            ErrorCode::BlockErrDaSetInvalid,
        )
        .expect_err("cancelled");
        assert_eq!(cancelled.code, ErrorCode::BlockErrDaSetInvalid);

        let panic_err = reduce_da_results(
            vec![WorkerResult {
                value: None,
                error: Some(WorkerPoolError::Panic("boom".to_string())),
            }],
            ErrorCode::BlockErrDaSetInvalid,
        )
        .expect_err("panic");
        assert_eq!(panic_err.code, ErrorCode::BlockErrDaSetInvalid);
    }

    #[test]
    fn da_run_error_to_tx_error_maps_pool_failures() {
        let invalid = da_run_error_to_tx_error(WorkerPoolRunError::InvalidMaxTasks);
        assert_eq!(invalid.code, ErrorCode::BlockErrDaSetInvalid);

        let budget = da_run_error_to_tx_error(WorkerPoolRunError::TooManyTasks {
            task_count: 2,
            max_tasks: 1,
        });
        assert_eq!(budget.code, ErrorCode::BlockErrDaBatchExceeded);
    }

    #[test]
    fn reduce_da_results_returns_first_task_error() {
        let err = TxError::new(ErrorCode::BlockErrDaChunkHashInvalid, "chunk_hash mismatch");
        let reduced = reduce_da_results(
            vec![
                WorkerResult {
                    value: Some(()),
                    error: None,
                },
                WorkerResult {
                    value: None,
                    error: Some(WorkerPoolError::Task(err.clone())),
                },
            ],
            ErrorCode::BlockErrDaSetInvalid,
        )
        .expect_err("task error");
        assert_eq!(reduced, err);
    }

    #[test]
    fn verify_da_chunk_hashes_parallel_bad_hash_returns_expected_code() {
        let err = verify_da_chunk_hashes_parallel(
            vec![DaChunkHashTask {
                tx_index: 1,
                da_payload: b"payload".to_vec(),
                expected: [0u8; 32],
            }],
            1,
        )
        .expect_err("bad hash");
        assert_eq!(err.code, ErrorCode::BlockErrDaChunkHashInvalid);
    }
}
