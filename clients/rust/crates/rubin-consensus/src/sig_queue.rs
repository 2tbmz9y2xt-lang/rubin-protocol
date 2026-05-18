use crate::constants::{MAX_BLOCK_WEIGHT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES};
use crate::error::{ErrorCode, TxError};
use crate::sig_cache::SigCache;
use crate::suite_registry::SuiteRegistry;
use crate::verify_sig_openssl::verify_sig_with_registry;
use crate::worker_pool::{
    run_worker_pool, WorkerCancellationToken, WorkerPoolError, WorkerPoolRunError, WorkerResult,
};

// Deferred sigcheck payload comes from witness bytes. Even in a maximally
// witness-heavy valid block, raw queued pubkey+signature bytes cannot exceed
// the block weight budget because witness data is charged 1:1 in weight.
const MAX_SIGCHECK_QUEUE_BYTES: usize = MAX_BLOCK_WEIGHT as usize;
const SIGCHECK_TASK_FIXED_OVERHEAD_BYTES: usize = 1 + 32 + 1;
const CURRENT_NATIVE_QUEUE_PAYLOAD_FLOOR_BYTES: u64 = ML_DSA_87_PUBKEY_BYTES + ML_DSA_87_SIG_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SigCheckTask {
    suite_id: u8,
    pubkey: Vec<u8>,
    sig: Vec<u8>,
    digest: [u8; 32],
    err_on_fail: TxError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigVerifyRequest {
    pub(crate) suite_id: u8,
    pub(crate) pubkey: Vec<u8>,
    pub(crate) sig: Vec<u8>,
    pub(crate) digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SigCheckQueueMark {
    len: usize,
    queued_bytes: usize,
}

/// SigCheckQueue collects deferred signature verification tasks during
/// sequential transaction validation. When flushed, it verifies all collected
/// signatures and returns the first error by submission order.
///
/// The queue stays deterministic even when multiple workers are configured:
/// batch execution may complete out of order internally, but the returned
/// error is always reduced by submission order.
#[derive(Debug)]
pub(crate) struct SigCheckQueue {
    tasks: Vec<SigCheckTask>,
    queued_bytes: usize,
    registry: Option<SuiteRegistry>,
    cache: Option<SigCache>,
    workers: usize,
}

impl Default for SigCheckQueue {
    fn default() -> Self {
        Self {
            tasks: Vec::new(),
            queued_bytes: 0,
            registry: None,
            cache: None,
            workers: 1,
        }
    }
}

#[cfg(test)]
impl Drop for SigCheckQueue {
    fn drop(&mut self) {
        if self.tasks.is_empty() || std::thread::panicking() {
            return;
        }
        panic!("SigCheckQueue dropped with unflushed tasks");
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl SigCheckQueue {
    pub(crate) fn new(workers: usize) -> Self {
        let workers = if workers == 0 {
            std::thread::available_parallelism()
                .map(|parallelism| parallelism.get())
                .unwrap_or(1)
        } else {
            workers
        };
        Self {
            tasks: Vec::new(),
            queued_bytes: 0,
            registry: None,
            cache: None,
            workers: workers.max(1),
        }
    }

    pub(crate) fn with_registry(mut self, registry: &SuiteRegistry) -> Self {
        self.registry = Some(registry.clone());
        self
    }

    pub(crate) fn with_cache(mut self, cache: SigCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub(crate) fn push(
        &mut self,
        suite_id: u8,
        pubkey: &[u8],
        sig: &[u8],
        digest: [u8; 32],
        err_on_fail: TxError,
    ) -> Result<(), TxError> {
        ensure_task_budget(self.tasks.len(), self.registry.as_ref())?;
        self.queued_bytes = next_queued_bytes(
            self.queued_bytes,
            sigcheck_task_bytes(pubkey.len(), sig.len())?,
        )?;
        self.tasks.push(SigCheckTask {
            suite_id,
            pubkey: pubkey.to_vec(),
            sig: sig.to_vec(),
            digest,
            err_on_fail,
        });
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(crate) fn flush(&mut self) -> Result<(), TxError> {
        if self.tasks.is_empty() {
            return Ok(());
        }

        let tasks = std::mem::take(&mut self.tasks);
        self.queued_bytes = 0;
        if tasks.len() == 1 || self.workers <= 1 {
            for task in tasks {
                verify_queued_task(task, self.registry.as_ref(), self.cache.as_ref())?;
            }
            return Ok(());
        }

        verify_queued_tasks_batch(
            tasks,
            self.workers,
            self.registry.as_ref(),
            self.cache.as_ref(),
        )
    }

    pub(crate) fn assert_flushed(&self) -> Result<(), TxError> {
        if self.tasks.is_empty() {
            return Ok(());
        }
        Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "SigCheckQueue has unflushed tasks",
        ))
    }

    pub(crate) fn mark(&self) -> SigCheckQueueMark {
        SigCheckQueueMark {
            len: self.tasks.len(),
            queued_bytes: self.queued_bytes,
        }
    }

    pub(crate) fn rollback_to(&mut self, mark: SigCheckQueueMark) {
        self.tasks.truncate(mark.len);
        self.queued_bytes = mark.queued_bytes;
    }

    fn ensure_registry(&mut self, registry: &SuiteRegistry) -> Result<(), TxError> {
        match &self.registry {
            Some(current) if current != registry => Err(TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "SigCheckQueue registry mismatch",
            )),
            Some(_) => Ok(()),
            None => {
                self.registry = Some(registry.clone());
                Ok(())
            }
        }
    }

    pub(crate) fn workers(&self) -> usize {
        self.workers
    }
}

pub(crate) fn queue_or_verify_signature(
    suite_id: u8,
    pubkey: &[u8],
    crypto_sig: &[u8],
    digest: [u8; 32],
    registry: &SuiteRegistry,
    sig_queue: &mut Option<&mut SigCheckQueue>,
    err_on_fail: TxError,
) -> Result<(), TxError> {
    if let Some(queue) = sig_queue.as_mut() {
        // Deferred mode changes only when signature errors are surfaced, not
        // the final accept/reject outcome. Structural checks still run inline.
        queue.ensure_registry(registry)?;
        queue.push(suite_id, pubkey, crypto_sig, digest, err_on_fail)?;
        return Ok(());
    }

    let ok = verify_sig_with_registry(suite_id, pubkey, crypto_sig, &digest, Some(registry))?;
    if !ok {
        return Err(err_on_fail);
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn verify_queued_task(
    task: SigCheckTask,
    registry: Option<&SuiteRegistry>,
    cache: Option<&SigCache>,
) -> Result<(), TxError> {
    if let Some(cache) = cache {
        if cache.lookup(task.suite_id, &task.pubkey, &task.sig, task.digest) {
            return Ok(());
        }
    }

    let ok = verify_sig_with_registry(
        task.suite_id,
        &task.pubkey,
        &task.sig,
        &task.digest,
        registry,
    )?;
    if !ok {
        return Err(task.err_on_fail);
    }
    if let Some(cache) = cache {
        cache.insert(task.suite_id, &task.pubkey, &task.sig, task.digest);
    }
    Ok(())
}

fn verify_queued_tasks_batch(
    tasks: Vec<SigCheckTask>,
    workers: usize,
    registry: Option<&SuiteRegistry>,
    cache: Option<&SigCache>,
) -> Result<(), TxError> {
    let token = WorkerCancellationToken::new();
    let max_tasks = tasks.len();
    let cache = cache.cloned();
    let results = run_worker_pool(&token, workers, max_tasks, tasks, |_cancel, task| {
        verify_queued_task(task, registry, cache.as_ref())
    })
    .map_err(sigcheck_batch_run_error_to_tx_error)?;

    reduce_queued_task_results(results)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_signatures_batch(
    tasks: Vec<SigVerifyRequest>,
    workers: usize,
) -> Vec<Option<TxError>> {
    if tasks.is_empty() {
        return Vec::new();
    }

    let max_tasks = tasks.len();
    verify_signatures_batch_with_limit(tasks, workers, max_tasks)
}

#[cfg_attr(not(test), allow(dead_code))]
fn verify_signatures_batch_with_limit(
    tasks: Vec<SigVerifyRequest>,
    workers: usize,
    max_tasks: usize,
) -> Vec<Option<TxError>> {
    let token = WorkerCancellationToken::new();
    let task_count = tasks.len();
    let registry = SuiteRegistry::default_registry();
    let results = match run_worker_pool(&token, workers, max_tasks, tasks, |_cancel, task| {
        let ok = verify_sig_with_registry(
            task.suite_id,
            &task.pubkey,
            &task.sig,
            &task.digest,
            Some(&registry),
        )?;
        if !ok {
            return Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "batch: signature invalid",
            ));
        }
        Ok(())
    }) {
        Ok(results) => results,
        Err(run_err) => {
            return vec![Some(sigcheck_batch_run_error_to_tx_error(run_err)); task_count];
        }
    };

    results
        .into_iter()
        .map(|result| result.error.map(worker_pool_sigcheck_error_to_tx_error))
        .collect()
}

fn reduce_queued_task_results(results: Vec<WorkerResult<(), TxError>>) -> Result<(), TxError> {
    // WorkerPool preserves submission order in its result vector. We reduce
    // the batch strictly in that order so the queue returns the same earliest
    // failing signature it would have surfaced sequentially.
    for result in results {
        match result.error {
            Some(WorkerPoolError::Task(err)) => return Err(err),
            Some(WorkerPoolError::Panic(_)) => {
                return Err(TxError::new(
                    ErrorCode::TxErrSigInvalid,
                    "signature worker panic (fail-closed)",
                ));
            }
            Some(WorkerPoolError::Cancelled) | None => {}
        }
    }
    Ok(())
}

fn worker_pool_sigcheck_error_to_tx_error(err: WorkerPoolError<TxError>) -> TxError {
    match err {
        WorkerPoolError::Task(err) => err,
        WorkerPoolError::Cancelled => TxError::new(
            ErrorCode::TxErrSigInvalid,
            "signature worker canceled (fail-closed)",
        ),
        WorkerPoolError::Panic(_) => TxError::new(
            ErrorCode::TxErrSigInvalid,
            "signature worker panic (fail-closed)",
        ),
    }
}

fn sigcheck_batch_run_error_to_tx_error(err: WorkerPoolRunError) -> TxError {
    match err {
        WorkerPoolRunError::InvalidMaxTasks => TxError::new(
            ErrorCode::TxErrSigInvalid,
            "signature batch worker pool misconfigured",
        ),
        WorkerPoolRunError::TooManyTasks { .. } => TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "signature batch task budget exceeded",
        ),
    }
}

fn ensure_task_budget(task_count: usize, registry: Option<&SuiteRegistry>) -> Result<(), TxError> {
    if task_count >= max_sigcheck_queue_tasks(registry)? {
        return Err(TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "SigCheckQueue task budget exceeded",
        ));
    }
    Ok(())
}

fn max_sigcheck_queue_tasks(registry: Option<&SuiteRegistry>) -> Result<usize, TxError> {
    let default_registry;
    let registry = match registry {
        Some(registry) => registry,
        None => {
            default_registry = SuiteRegistry::default_registry();
            &default_registry
        }
    };
    let min_payload_bytes = registry
        .min_sigcheck_payload_bytes()
        .map_err(|msg| TxError::new(ErrorCode::TxErrSigAlgInvalid, msg))?
        .ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrSigAlgInvalid,
                "SigCheckQueue registry has no registered suites",
            )
        })?;
    let effective_min_payload_bytes =
        min_payload_bytes.max(CURRENT_NATIVE_QUEUE_PAYLOAD_FLOOR_BYTES);
    let min_task_bytes = (SIGCHECK_TASK_FIXED_OVERHEAD_BYTES as u64)
        .checked_add(effective_min_payload_bytes)
        .ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrWitnessOverflow,
                "SigCheckQueue task budget footprint overflow",
            )
        })?;
    let max_tasks = (MAX_SIGCHECK_QUEUE_BYTES as u64) / min_task_bytes;
    debug_assert!(max_tasks <= (MAX_SIGCHECK_QUEUE_BYTES as u64));
    Ok(max_tasks as usize)
}

fn next_queued_bytes(current: usize, task_bytes: usize) -> Result<usize, TxError> {
    let next = current.checked_add(task_bytes).ok_or_else(|| {
        TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "SigCheckQueue queued-byte accounting overflow",
        )
    })?;
    if next > MAX_SIGCHECK_QUEUE_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "SigCheckQueue queued-byte budget exceeded",
        ));
    }
    Ok(next)
}

fn sigcheck_task_bytes(pubkey_len: usize, sig_len: usize) -> Result<usize, TxError> {
    SIGCHECK_TASK_FIXED_OVERHEAD_BYTES
        .checked_add(pubkey_len)
        .and_then(|next| next.checked_add(sig_len))
        .ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrWitnessOverflow,
                "SigCheckQueue task footprint overflow",
            )
        })
}

#[cfg(test)]
#[path = "sig_queue_batch_tests.rs"]
mod batch_tests;
#[cfg(test)]
#[path = "sig_queue_budget_tests.rs"]
mod budget_tests;
#[cfg(test)]
#[path = "sig_queue_deferred_spend_tests.rs"]
mod deferred_spend_tests;
#[cfg(test)]
#[path = "sig_queue_htlc_tests.rs"]
mod htlc_tests;
#[cfg(test)]
#[path = "sig_queue_p2pk_stealth_tests.rs"]
mod p2pk_stealth_tests;
#[cfg(test)]
#[path = "sig_queue_queue_tests.rs"]
mod queue_tests;
#[cfg(test)]
#[path = "sig_queue_test_support.rs"]
mod test_support;
#[cfg(test)]
#[path = "sig_queue_threshold_tests.rs"]
mod threshold_tests;
