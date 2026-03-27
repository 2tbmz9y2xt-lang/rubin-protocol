use std::collections::HashMap;

use crate::constants::COV_TYPE_DA_COMMIT;
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
        let total_len: usize = task
            .chunk_payloads
            .iter()
            .map(Vec::len)
            .try_fold(0usize, |acc, len| acc.checked_add(len))
            .ok_or_else(|| {
                TxError::new(
                    ErrorCode::BlockErrDaPayloadCommitInvalid,
                    "payload commitment concat overflow",
                )
            })?;
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

pub fn collect_da_payload_commit_tasks(txs: &[Tx]) -> Vec<DaPayloadCommitTask> {
    let mut commits: HashMap<[u8; 32], &Tx> = HashMap::new();
    let mut chunks: HashMap<[u8; 32], HashMap<u16, &Tx>> = HashMap::new();

    for tx in txs {
        match tx.tx_kind {
            0x01 => {
                let Some(core) = tx.da_commit_core.as_ref() else {
                    continue;
                };
                commits.insert(core.da_id, tx);
            }
            0x02 => {
                let Some(core) = tx.da_chunk_core.as_ref() else {
                    continue;
                };
                chunks
                    .entry(core.da_id)
                    .or_default()
                    .insert(core.chunk_index, tx);
            }
            _ => {}
        }
    }

    if commits.is_empty() {
        return Vec::new();
    }

    let mut ids: Vec<[u8; 32]> = commits.keys().copied().collect();
    ids.sort_unstable();

    let mut tasks = Vec::with_capacity(ids.len());
    for da_id in ids {
        let commit_tx = commits
            .get(&da_id)
            .copied()
            .expect("sorted IDs come from commit map");
        let commit_core = commit_tx
            .da_commit_core
            .as_ref()
            .expect("commit map stores only DA commit txs");
        let chunk_count = commit_core.chunk_count;
        let chunk_set = chunks.get(&da_id);

        let mut chunk_payloads = Vec::with_capacity(chunk_count as usize);
        for chunk_index in 0..chunk_count {
            let payload = chunk_set
                .and_then(|set| set.get(&chunk_index))
                .map(|tx| tx.da_payload.clone())
                .unwrap_or_default();
            chunk_payloads.push(payload);
        }

        let mut expected_commit = [0u8; 32];
        for output in &commit_tx.outputs {
            if output.covenant_type == COV_TYPE_DA_COMMIT && output.covenant_data.len() == 32 {
                expected_commit.copy_from_slice(&output.covenant_data);
                break;
            }
        }

        tasks.push(DaPayloadCommitTask {
            da_id,
            chunk_count,
            chunk_payloads,
            expected_commit,
        });
    }

    tasks
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
