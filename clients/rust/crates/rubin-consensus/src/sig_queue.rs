use crate::constants::{MAX_BLOCK_WEIGHT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES};
use crate::error::{ErrorCode, TxError};
use crate::sig_cache::SigCache;
use crate::suite_registry::SuiteRegistry;
use crate::verify_sig_openssl::{verify_sig, verify_sig_with_registry};
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

    let ok = match registry {
        Some(registry) => verify_sig_with_registry(
            task.suite_id,
            &task.pubkey,
            &task.sig,
            &task.digest,
            Some(registry),
        )?,
        None => verify_sig(task.suite_id, &task.pubkey, &task.sig, &task.digest)?,
    };
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
mod tests {
    use super::*;
    use crate::compactsize::encode_compact_size;
    use crate::constants::{
        COV_TYPE_EXT, COV_TYPE_HTLC, COV_TYPE_P2PK, COV_TYPE_STEALTH, LOCK_MODE_HEIGHT,
        MAX_HTLC_COVENANT_DATA, MAX_STEALTH_COVENANT_DATA, ML_DSA_87_PUBKEY_BYTES,
        ML_DSA_87_SIG_BYTES, ML_KEM_1024_CT_BYTES, SIGHASH_ALL, SUITE_ID_ML_DSA_87,
        SUITE_ID_SENTINEL, VERIFY_COST_ML_DSA_87,
    };
    use crate::core_ext::{
        parse_core_ext_covenant_data, validate_core_ext_spend_with_cache_and_suite_context_q,
        CoreExtActiveProfile, CoreExtProfiles, CoreExtVerificationBinding,
    };
    use crate::hash::sha3_256;
    use crate::htlc::parse_htlc_covenant_data;
    use crate::htlc::validate_htlc_spend_q;
    use crate::sig_cache::SigCache;
    use crate::spend_verify::{validate_p2pk_spend_q, validate_threshold_sig_spend_q};
    use crate::stealth::parse_stealth_covenant_data;
    use crate::stealth::validate_stealth_spend_q;
    use crate::suite_registry::SuiteParams;
    use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
    use crate::tx_helpers::p2pk_covenant_data_for_pubkey;
    use crate::utxo_basic::UtxoEntry;
    use crate::verify_sig_openssl::Mldsa87Keypair;
    use crate::{sighash_v1_digest_with_cache, SighashV1PrehashCache};
    use std::collections::BTreeMap;

    fn test_tx_context() -> (Tx, u32, u64, [u8; 32]) {
        let mut prev = [0u8; 32];
        prev[0] = 0x42;
        let mut chain_id = [0u8; 32];
        chain_id[0] = 0x11;
        (
            Tx {
                version: 1,
                tx_kind: 0x00,
                tx_nonce: 7,
                inputs: vec![TxInput {
                    prev_txid: prev,
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 0,
                }],
                outputs: vec![TxOutput {
                    value: 90,
                    covenant_type: COV_TYPE_P2PK,
                    covenant_data: vec![0u8; 33],
                }],
                locktime: 0,
                witness: vec![],
                da_payload: vec![],
                da_commit_core: None,
                da_chunk_core: None,
            },
            0,
            100,
            chain_id,
        )
    }

    fn sign_witness(
        keypair: &Mldsa87Keypair,
        tx: &Tx,
        input_index: u32,
        input_value: u64,
        chain_id: [u8; 32],
    ) -> WitnessItem {
        let mut cache = SighashV1PrehashCache::new(tx).expect("cache");
        let digest = sighash_v1_digest_with_cache(
            &mut cache,
            input_index,
            input_value,
            chain_id,
            SIGHASH_ALL,
        )
        .expect("digest");
        let mut signature = keypair.sign_digest32(digest).expect("sign");
        signature.push(SIGHASH_ALL);
        WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: keypair.pubkey_bytes(),
            signature,
        }
    }

    #[test]
    fn sig_check_queue_with_cache_single_hit() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let cache = SigCache::new(100);
        let digest = [0x42; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");
        let pubkey = keypair.pubkey_bytes();

        cache.insert(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest);

        let mut queue = SigCheckQueue::new(1).with_cache(cache.clone());
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &pubkey,
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "test"),
            )
            .expect("push");
        queue.flush().expect("flush");

        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn sig_check_queue_with_cache_invalid_not_cached() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let cache = SigCache::new(100);
        let digest = [0x42; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");
        let pubkey = keypair.pubkey_bytes();
        let mut bad_digest = digest;
        bad_digest[0] ^= 0xff;

        let mut queue = SigCheckQueue::new(1).with_cache(cache.clone());
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &pubkey,
                &sig,
                bad_digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "invalid"),
            )
            .expect("push");

        let err = queue.flush().expect_err("invalid signature must fail");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert_eq!(cache.len(), 0);
    }

    fn encode_htlc_claim_payload(preimage: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + preimage.len());
        out.push(0x00);
        out.extend_from_slice(&(preimage.len() as u16).to_le_bytes());
        out.extend_from_slice(preimage);
        out
    }

    fn make_stealth_entry(one_time_key_id: [u8; 32]) -> UtxoEntry {
        let mut out = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
        out[ML_KEM_1024_CT_BYTES as usize..].copy_from_slice(&one_time_key_id);
        UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_STEALTH,
            covenant_data: out,
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    fn core_ext_covdata(ext_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_id.to_le_bytes());
        encode_compact_size(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    fn core_ext_profiles(ext_id: u16) -> CoreExtProfiles {
        CoreExtProfiles {
            active: vec![CoreExtActiveProfile {
                ext_id,
                tx_context_enabled: false,
                allowed_suite_ids: vec![SUITE_ID_ML_DSA_87],
                verification_binding: CoreExtVerificationBinding::NativeVerifySig,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: Vec::new(),
                ext_payload_schema: Vec::new(),
            }],
        }
    }

    #[test]
    fn sig_check_queue_returns_first_failure_by_submission_order() {
        let keypair_a = Mldsa87Keypair::generate().expect("keypair a");
        let keypair_b = Mldsa87Keypair::generate().expect("keypair b");
        let keypair_c = Mldsa87Keypair::generate().expect("keypair c");
        let digest_a = [0x11; 32];
        let digest_b = [0x22; 32];

        let bad_sig_a = keypair_b.sign_digest32(digest_a).expect("bad sig a");
        let bad_sig_b = keypair_c.sign_digest32(digest_b).expect("bad sig b");

        let mut queue = SigCheckQueue::new(2);
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &keypair_a.pubkey_bytes(),
                &bad_sig_a,
                digest_a,
                TxError::new(ErrorCode::TxErrSigInvalid, "first failure"),
            )
            .expect("enqueue first");
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &keypair_b.pubkey_bytes(),
                &bad_sig_b,
                digest_b,
                TxError::new(ErrorCode::TxErrSigInvalid, "second failure"),
            )
            .expect("enqueue second");

        let err = queue.flush().expect_err("flush must fail");
        assert_eq!(
            err,
            TxError::new(ErrorCode::TxErrSigInvalid, "first failure")
        );
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn sig_check_queue_new_zero_workers_defaults_to_parallelism() {
        let queue = SigCheckQueue::new(0);
        assert!(
            queue.workers() >= 1,
            "zero workers must normalize to available parallelism"
        );
    }

    #[test]
    fn sig_check_queue_is_reusable_after_flush() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0x33; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");

        let mut queue = SigCheckQueue::new(1);
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &keypair.pubkey_bytes(),
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
            )
            .expect("enqueue batch one");
        queue.flush().expect("first flush");
        assert!(queue.is_empty(), "queue empty after first flush");

        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &keypair.pubkey_bytes(),
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
            )
            .expect("enqueue batch two");
        queue.flush().expect("second flush");
        assert!(queue.is_empty(), "queue empty after second flush");
        queue.assert_flushed().expect("assert flushed");
    }

    #[test]
    fn sig_check_queue_zero_value_flush_fails_closed() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");

        let mut queue = SigCheckQueue::default();
        assert_eq!(queue.workers(), 1, "zero-value queue normalizes workers");
        for i in 0..4u8 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            let sig = keypair.sign_digest32(digest).expect("sign");
            queue
                .push(
                    SUITE_ID_ML_DSA_87,
                    &keypair.pubkey_bytes(),
                    &sig,
                    digest,
                    TxError::new(ErrorCode::TxErrSigInvalid, "zero-value"),
                )
                .expect("enqueue valid zero-value");
        }
        queue.flush().expect("valid zero-value flush");

        for i in 0..4u8 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            let sig = keypair.sign_digest32(digest).expect("sign");
            digest[0] ^= 0xff;
            queue
                .push(
                    SUITE_ID_ML_DSA_87,
                    &keypair.pubkey_bytes(),
                    &sig,
                    digest,
                    TxError::new(ErrorCode::TxErrSigInvalid, "zero-value-invalid"),
                )
                .expect("enqueue invalid zero-value");
        }
        assert!(queue.flush().is_err(), "invalid zero-value flush must fail");
        queue
            .assert_flushed()
            .expect("assert flushed after failure");
    }

    #[test]
    fn sig_check_queue_len_tracks_unflushed_tasks() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0x44; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");

        let mut queue = SigCheckQueue::new(1);
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &keypair.pubkey_bytes(),
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "test"),
            )
            .expect("enqueue");

        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
        queue.flush().expect("cleanup flush");
    }

    #[test]
    fn sig_check_queue_single_bad_suite_error() {
        let mut queue = SigCheckQueue::new(1);
        queue
            .push(
                0xfe,
                b"fake-pubkey",
                b"fake-sig",
                [0u8; 32],
                TxError::new(ErrorCode::TxErrSigInvalid, "test"),
            )
            .expect("enqueue bad suite");
        assert!(queue.flush().is_err(), "bad suite id must fail");
        queue
            .assert_flushed()
            .expect("assert flushed after bad suite");
    }

    #[test]
    fn sig_check_queue_assert_flushed_rejects_pending_tasks() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0x45; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");
        let mut queue = SigCheckQueue::new(0);

        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &keypair.pubkey_bytes(),
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
            )
            .expect("enqueue");

        let err = queue.assert_flushed().expect_err("pending tasks must fail");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        queue
            .flush()
            .expect("cleanup queued task after fail-closed check");
    }

    #[test]
    fn sig_check_queue_empty_flush_is_ok() {
        let mut queue = SigCheckQueue::new(1);
        queue.flush().expect("empty flush");
    }

    #[test]
    fn verify_signatures_batch_all_valid() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let tasks = (0..4u8)
            .map(|i| {
                let mut digest = [0u8; 32];
                digest[0] = i;
                let sig = keypair.sign_digest32(digest).expect("sign");
                SigVerifyRequest {
                    suite_id: SUITE_ID_ML_DSA_87,
                    pubkey: keypair.pubkey_bytes(),
                    sig,
                    digest,
                }
            })
            .collect::<Vec<_>>();

        let results = verify_signatures_batch(tasks, 2);
        assert_eq!(results, vec![None, None, None, None]);
    }

    #[test]
    fn verify_signatures_batch_mixed_validity_preserves_alignment() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let tasks = (0..4u8)
            .map(|i| {
                let mut digest = [0u8; 32];
                digest[0] = i;
                let sig = keypair.sign_digest32(digest).expect("sign");
                if i == 1 || i == 3 {
                    digest[1] ^= 0xff;
                }
                SigVerifyRequest {
                    suite_id: SUITE_ID_ML_DSA_87,
                    pubkey: keypair.pubkey_bytes(),
                    sig,
                    digest,
                }
            })
            .collect::<Vec<_>>();

        let results = verify_signatures_batch(tasks, 4);
        assert!(results[0].is_none(), "task 0 must be valid");
        assert_eq!(
            results[1],
            Some(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "batch: signature invalid"
            ))
        );
        assert!(results[2].is_none(), "task 2 must be valid");
        assert_eq!(
            results[3],
            Some(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "batch: signature invalid"
            ))
        );
    }

    #[test]
    fn verify_signatures_batch_empty_is_empty() {
        assert!(verify_signatures_batch(Vec::new(), 4).is_empty());
    }

    #[test]
    fn reduce_queued_task_results_maps_worker_panic_fail_closed() {
        let err = reduce_queued_task_results(vec![
            WorkerResult {
                value: Some(()),
                error: None,
            },
            WorkerResult {
                value: None,
                error: Some(WorkerPoolError::Cancelled),
            },
            WorkerResult {
                value: None,
                error: Some(WorkerPoolError::Panic("boom".to_string())),
            },
        ])
        .expect_err("panic must fail closed");

        assert_eq!(
            err,
            TxError::new(
                ErrorCode::TxErrSigInvalid,
                "signature worker panic (fail-closed)"
            )
        );
    }

    #[test]
    fn reduce_queued_task_results_ignores_cancelled_tail_without_error() {
        reduce_queued_task_results(vec![
            WorkerResult {
                value: Some(()),
                error: None,
            },
            WorkerResult {
                value: None,
                error: Some(WorkerPoolError::Cancelled),
            },
        ])
        .expect("cancelled tail without preceding task error is ignored");
    }

    #[test]
    fn verify_signatures_batch_run_error_maps_all_results() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let tasks = (0..2u8)
            .map(|i| {
                let mut digest = [0u8; 32];
                digest[0] = i;
                let sig = keypair.sign_digest32(digest).expect("sign");
                SigVerifyRequest {
                    suite_id: SUITE_ID_ML_DSA_87,
                    pubkey: keypair.pubkey_bytes(),
                    sig,
                    digest,
                }
            })
            .collect::<Vec<_>>();

        let results = verify_signatures_batch_with_limit(tasks, 2, 1);
        assert_eq!(
            results,
            vec![
                Some(TxError::new(
                    ErrorCode::TxErrWitnessOverflow,
                    "signature batch task budget exceeded",
                )),
                Some(TxError::new(
                    ErrorCode::TxErrWitnessOverflow,
                    "signature batch task budget exceeded",
                )),
            ]
        );
    }

    #[test]
    fn sig_check_queue_assert_flushed_accepts_after_explicit_flush() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0x77; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");
        let mut queue = SigCheckQueue::new(1);
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &keypair.pubkey_bytes(),
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
            )
            .expect("enqueue");
        queue.flush().expect("flush");
        queue.assert_flushed().expect("assert flushed");
    }

    #[test]
    #[should_panic(expected = "SigCheckQueue dropped with unflushed tasks")]
    fn sig_check_queue_drop_panics_on_invalid_pending_task() {
        let mut queue = SigCheckQueue::new(1);
        queue
            .push(
                0xfe,
                b"fake-pubkey",
                b"fake-sig",
                [0u8; 32],
                TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
            )
            .expect("enqueue");
    }

    #[test]
    fn queue_or_verify_signature_auto_wires_registry() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0x55; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");
        let registry = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1);
        let mut maybe_queue = Some(&mut queue);

        queue_or_verify_signature(
            SUITE_ID_ML_DSA_87,
            &keypair.pubkey_bytes(),
            &sig,
            digest,
            &registry,
            &mut maybe_queue,
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        )
        .expect("enqueue with registry");

        assert_eq!(queue.registry.as_ref(), Some(&registry));
        queue.flush().expect("flush");
    }

    #[test]
    fn queue_or_verify_signature_rejects_registry_mismatch() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0x66; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");

        let current_registry = SuiteRegistry::default_registry();
        let mut suites = BTreeMap::new();
        suites.insert(
            SUITE_ID_ML_DSA_87,
            SuiteParams {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        suites.insert(
            0x44,
            SuiteParams {
                suite_id: 0x44,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        let mismatched_registry = SuiteRegistry::with_suites(suites);

        let mut queue = SigCheckQueue::new(1).with_registry(&current_registry);
        let mut maybe_queue = Some(&mut queue);
        let err = queue_or_verify_signature(
            SUITE_ID_ML_DSA_87,
            &keypair.pubkey_bytes(),
            &sig,
            digest,
            &mismatched_registry,
            &mut maybe_queue,
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        )
        .expect_err("mismatched registry must fail");

        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn sig_check_queue_rejects_byte_budget_overflow() {
        let mut queue = SigCheckQueue::new(1);
        queue.queued_bytes = MAX_SIGCHECK_QUEUE_BYTES;

        let err = queue
            .push(
                SUITE_ID_ML_DSA_87,
                b"p",
                b"s",
                [0u8; 32],
                TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
            )
            .expect_err("byte budget overflow must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
    }

    #[test]
    fn sig_check_queue_rejects_task_budget_overflow() {
        let limit = max_sigcheck_queue_tasks(None).expect("default registry");
        let err =
            ensure_task_budget(limit, None).expect_err("task budget boundary must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
    }

    #[test]
    fn sig_check_queue_rejects_empty_registry_task_budget() {
        let registry = SuiteRegistry::with_suites(BTreeMap::new());
        let err =
            max_sigcheck_queue_tasks(Some(&registry)).expect_err("empty registry must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
        assert_eq!(err.msg, "SigCheckQueue registry has no registered suites");
    }

    #[test]
    fn sig_check_queue_task_budget_footprint_overflow_fails_closed() {
        let mut suites = BTreeMap::new();
        suites.insert(
            SUITE_ID_ML_DSA_87,
            SuiteParams {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey_len: u64::MAX,
                sig_len: 0,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        let registry = SuiteRegistry::with_suites(suites);

        let err = max_sigcheck_queue_tasks(Some(&registry))
            .expect_err("task footprint overflow must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
        assert_eq!(err.msg, "SigCheckQueue task budget footprint overflow");
    }

    #[test]
    fn sig_check_queue_byte_budget_is_bounded_by_block_weight() {
        assert_eq!(MAX_SIGCHECK_QUEUE_BYTES, MAX_BLOCK_WEIGHT as usize);
    }

    #[test]
    fn sig_check_queue_task_budget_is_bounded_by_smallest_native_payload() {
        let registry = SuiteRegistry::default_registry();
        assert_eq!(
            max_sigcheck_queue_tasks(Some(&registry)).expect("default registry"),
            usize::try_from(
                (MAX_SIGCHECK_QUEUE_BYTES as u64)
                    / ((SIGCHECK_TASK_FIXED_OVERHEAD_BYTES as u64)
                        + registry
                            .min_sigcheck_payload_bytes()
                            .expect("payload lookup")
                            .expect("mldsa payload")
                            .max(CURRENT_NATIVE_QUEUE_PAYLOAD_FLOOR_BYTES))
            )
            .expect("fits usize")
        );
    }

    #[test]
    fn sig_check_queue_task_budget_does_not_widen_below_current_native_floor() {
        let mut suites = BTreeMap::new();
        suites.insert(
            SUITE_ID_ML_DSA_87,
            SuiteParams {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: 64,
                sig_len: 100,
                verify_cost: 1,
                alg_name: "ML-DSA-87",
            },
        );
        let registry = SuiteRegistry::with_suites(suites);

        assert_eq!(
            max_sigcheck_queue_tasks(Some(&registry)).expect("custom registry"),
            max_sigcheck_queue_tasks(None).expect("default registry")
        );
    }

    #[test]
    fn next_queued_bytes_overflow_fails_closed() {
        let err = next_queued_bytes(usize::MAX, 1).expect_err("usize overflow must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
    }

    #[test]
    fn sigcheck_task_bytes_overflow_fails_closed() {
        let err =
            sigcheck_task_bytes(usize::MAX, 1).expect_err("footprint overflow must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
    }

    #[test]
    fn sigcheck_task_bytes_is_architecture_independent() {
        let bytes = sigcheck_task_bytes(10, 20).expect("accounting");
        assert_eq!(bytes, SIGCHECK_TASK_FIXED_OVERHEAD_BYTES + 30);
    }

    #[test]
    fn validate_p2pk_spend_q_defers_and_flushes() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let pubkey = keypair.pubkey_bytes();
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, input_index, input_value, chain_id) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
        let registry = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&registry);

        validate_p2pk_spend_q(
            &entry,
            &witness,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&registry),
        )
        .expect("queued p2pk");
        assert_eq!(queue.len(), 1);
        queue.flush().expect("flush");
        assert!(queue.is_empty(), "queue empty after flush");
    }

    #[test]
    fn validate_threshold_sig_spend_q_defers_and_flushes() {
        let kp1 = Mldsa87Keypair::generate().expect("kp1");
        let kp2 = Mldsa87Keypair::generate().expect("kp2");
        let key_id_1 = sha3_256(&kp1.pubkey_bytes());
        let key_id_2 = sha3_256(&kp2.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&kp1, &tx, input_index, input_value, chain_id);
        let registry = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&registry);

        validate_threshold_sig_spend_q(
            &[key_id_1, key_id_2],
            1,
            &[
                witness,
                WitnessItem {
                    suite_id: SUITE_ID_SENTINEL,
                    pubkey: Vec::new(),
                    signature: Vec::new(),
                },
            ],
            input_index,
            input_value,
            chain_id,
            0,
            "TEST_THRESHOLD",
            &mut cache,
            Some(&mut queue),
            None,
            Some(&registry),
        )
        .expect("queued threshold");
        assert_eq!(queue.len(), 1);
        queue.flush().expect("flush");
    }

    #[test]
    fn validate_threshold_sig_spend_q_rolls_back_queue_on_threshold_failure() {
        let kp1 = Mldsa87Keypair::generate().expect("kp1");
        let kp2 = Mldsa87Keypair::generate().expect("kp2");
        let key_id_1 = sha3_256(&kp1.pubkey_bytes());
        let key_id_2 = sha3_256(&kp2.pubkey_bytes());
        let (tx, input_index, input_value, chain_id) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&kp1, &tx, input_index, input_value, chain_id);
        let registry = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&registry);

        let err = validate_threshold_sig_spend_q(
            &[key_id_1, key_id_2],
            2,
            &[
                witness,
                WitnessItem {
                    suite_id: SUITE_ID_SENTINEL,
                    pubkey: Vec::new(),
                    signature: Vec::new(),
                },
            ],
            input_index,
            input_value,
            chain_id,
            0,
            "TEST_THRESHOLD",
            &mut cache,
            Some(&mut queue),
            None,
            Some(&registry),
        )
        .expect_err("threshold failure must reject");

        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert!(
            queue.is_empty(),
            "threshold failure must roll back queued tasks"
        );
    }

    #[test]
    fn validate_htlc_spend_q_defers_and_flushes() {
        let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
        let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
        let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
        let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
        let preimage = b"sig-queue-htlc-ok";
        let entry = {
            let mut out = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
            out.extend_from_slice(&sha3_256(preimage));
            out.push(LOCK_MODE_HEIGHT);
            out.extend_from_slice(&1u64.to_le_bytes());
            out.extend_from_slice(&claim_key_id);
            out.extend_from_slice(&refund_key_id);
            UtxoEntry {
                value: 1000,
                covenant_type: COV_TYPE_HTLC,
                covenant_data: out,
                creation_height: 0,
                created_by_coinbase: false,
            }
        };
        let (tx, input_index, input_value, chain_id) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let sig_item = sign_witness(&claim_kp, &tx, input_index, input_value, chain_id);
        let path_item = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: claim_key_id.to_vec(),
            signature: encode_htlc_claim_payload(preimage),
        };
        let registry = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&registry);

        validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            input_index,
            input_value,
            chain_id,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&registry),
        )
        .expect("queued htlc");
        assert_eq!(queue.len(), 1);
        queue.flush().expect("flush");
        assert!(parse_htlc_covenant_data(&entry.covenant_data).is_ok());
    }

    #[test]
    fn validate_stealth_spend_q_defers_and_flushes() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let one_time_key_id = sha3_256(&keypair.pubkey_bytes());
        let entry = make_stealth_entry(one_time_key_id);
        let (tx, input_index, input_value, chain_id) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
        let registry = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&registry);

        validate_stealth_spend_q(
            &entry,
            &witness,
            input_index,
            input_value,
            chain_id,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&registry),
        )
        .expect("queued stealth");
        assert_eq!(queue.len(), 1);
        queue.flush().expect("flush");
        assert!(parse_stealth_covenant_data(&entry.covenant_data).is_ok());
    }

    #[test]
    fn validate_core_ext_native_q_defers_and_flushes() {
        let ext_id = 7u16;
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let entry = UtxoEntry {
            value: 1,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(ext_id, b""),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let profiles = core_ext_profiles(ext_id);
        let (tx, input_index, input_value, chain_id) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&keypair, &tx, input_index, input_value, chain_id);
        let registry = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&registry);

        validate_core_ext_spend_with_cache_and_suite_context_q(
            &entry,
            &witness,
            input_index,
            input_value,
            chain_id,
            0,
            &profiles,
            None,
            Some(&registry),
            None,
            Some(&mut queue),
            &mut cache,
        )
        .expect("queued core_ext");
        assert_eq!(queue.len(), 1);
        queue.flush().expect("flush");
        assert!(parse_core_ext_covenant_data(&entry.covenant_data).is_ok());
    }

    // --- Helper: build a valid HTLC claim fixture, returns (entry, path_item, sig_item, queue) ---
    fn htlc_claim_fixture() -> (
        UtxoEntry,
        WitnessItem,
        WitnessItem,
        Tx,
        u32,
        u64,
        [u8; 32],
        SuiteRegistry,
    ) {
        let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
        let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
        let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
        let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
        let preimage = b"htlc-fixture-preimage";
        let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
        cov.extend_from_slice(&sha3_256(preimage));
        cov.push(LOCK_MODE_HEIGHT);
        cov.extend_from_slice(&100u64.to_le_bytes());
        cov.extend_from_slice(&claim_key_id);
        cov.extend_from_slice(&refund_key_id);
        let entry = UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: cov,
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, input_index, input_value, chain_id) = test_tx_context();
        let sig_item = sign_witness(&claim_kp, &tx, input_index, input_value, chain_id);
        let path_item = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: claim_key_id.to_vec(),
            signature: encode_htlc_claim_payload(preimage),
        };
        let registry = SuiteRegistry::default_registry();
        (
            entry,
            path_item,
            sig_item,
            tx,
            input_index,
            input_value,
            chain_id,
            registry,
        )
    }

    // HTLC Error Path Tests (11)

    #[test]
    fn validate_htlc_claim_payload_suite_id_mismatch_q() {
        // path_item.suite_id must be SENTINEL
        let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        path_item.suite_id = SUITE_ID_ML_DSA_87; // wrong: not SENTINEL
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-SENTINEL selector");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_htlc_claim_selector_key_length_invalid_q() {
        // path_item.pubkey must be exactly 32 bytes
        let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        path_item.pubkey = vec![0u8; 16]; // wrong length
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-32-byte selector key");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_htlc_claim_payload_empty_q() {
        // path_item.signature (payload) cannot be empty
        let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        path_item.signature = vec![]; // empty
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject empty payload");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_htlc_unknown_path_byte_q() {
        // First byte of claim payload must be 0x00 (claim) or 0x01 (refund)
        let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        path_item.signature[0] = 0xFF; // invalid path selector
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject unknown path byte");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_htlc_preimage_too_short_q() {
        // Preimage shorter than MIN_HTLC_PREIMAGE_BYTES (16)
        let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
        let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
        let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
        let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
        let short_preimage = b"tiny"; // 4 bytes < 16
        let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
        cov.extend_from_slice(&sha3_256(short_preimage.as_slice()));
        cov.push(LOCK_MODE_HEIGHT);
        cov.extend_from_slice(&100u64.to_le_bytes());
        cov.extend_from_slice(&claim_key_id);
        cov.extend_from_slice(&refund_key_id);
        let entry = UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: cov,
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let sig_item = sign_witness(&claim_kp, &tx, ii, iv, cid);
        let path_item = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: claim_key_id.to_vec(),
            signature: encode_htlc_claim_payload(short_preimage),
        };
        let reg = SuiteRegistry::default_registry();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject short preimage");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_htlc_preimage_hash_mismatch_q() {
        // Valid-length preimage that doesn't match the stored hash
        let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        // Replace preimage with different valid-length data
        let bad_preimage = b"wrong-preimage-1234!";
        path_item.signature = encode_htlc_claim_payload(bad_preimage);
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject wrong preimage");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn validate_htlc_claim_key_id_mismatch_q() {
        // Selector key_id doesn't match claim_key_id in covenant
        let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        path_item.pubkey = vec![0xAA; 32]; // wrong key_id
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject wrong claim key_id");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn validate_htlc_refund_timelock_not_met_q() {
        // Refund path with block_height below lock_value
        let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
        let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
        let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
        let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
        let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
        cov.extend_from_slice(&sha3_256(b"refund-preimage-test"));
        cov.push(LOCK_MODE_HEIGHT);
        cov.extend_from_slice(&500u64.to_le_bytes()); // lock at height 500
        cov.extend_from_slice(&claim_key_id);
        cov.extend_from_slice(&refund_key_id);
        let entry = UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: cov,
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let sig_item = sign_witness(&refund_kp, &tx, ii, iv, cid);
        // Refund path: path_id=0x01
        let path_item = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: refund_key_id.to_vec(),
            signature: vec![0x01], // refund path
        };
        let reg = SuiteRegistry::default_registry();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            10, // block_height=10, below lock_value=500
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject: timelock not met");
        assert_eq!(err.code, ErrorCode::TxErrTimelockNotMet);
    }

    #[test]
    fn validate_htlc_refund_key_id_mismatch_q() {
        // Refund path with wrong selector key_id
        let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
        let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
        let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
        let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
        let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
        cov.extend_from_slice(&sha3_256(b"refund-key-mismatch"));
        cov.push(LOCK_MODE_HEIGHT);
        cov.extend_from_slice(&1u64.to_le_bytes());
        cov.extend_from_slice(&claim_key_id);
        cov.extend_from_slice(&refund_key_id);
        let entry = UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: cov,
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let sig_item = sign_witness(&refund_kp, &tx, ii, iv, cid);
        let path_item = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![0xBB; 32], // wrong refund key_id
            signature: vec![0x01],
        };
        let reg = SuiteRegistry::default_registry();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            100,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject wrong refund key_id");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn validate_htlc_claim_suite_not_native_q() {
        // sig_item with a suite_id not in native spend set
        let (entry, path_item, mut sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        sig_item.suite_id = 0xFE; // unknown suite
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-native suite");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn validate_htlc_claim_sig_non_canonical_q() {
        // sig_item with correct suite but wrong pubkey/sig lengths
        let (entry, path_item, mut sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        sig_item.pubkey = vec![0u8; 10]; // wrong pubkey length (not 2592)
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-canonical lengths");
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    // Threshold Error Path Tests (5)

    #[test]
    fn validate_threshold_slot_count_mismatch_q() {
        // ws.len() != keys.len()
        let kp1 = Mldsa87Keypair::generate().expect("kp1");
        let key_id_1 = sha3_256(&kp1.pubkey_bytes());
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&kp1, &tx, ii, iv, cid);
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        // 2 keys but only 1 witness slot
        let err = validate_threshold_sig_spend_q(
            &[key_id_1, [0xAA; 32]],
            1,
            &[witness],
            ii,
            iv,
            cid,
            0,
            "TEST",
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject slot count mismatch");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_threshold_sentinel_with_data_q() {
        // SENTINEL witness slot with non-empty pubkey
        let kp1 = Mldsa87Keypair::generate().expect("kp1");
        let key_id_1 = sha3_256(&kp1.pubkey_bytes());
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let bad_sentinel = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![0x42; 32], // SENTINEL must have empty pubkey
            signature: Vec::new(),
        };
        let err = validate_threshold_sig_spend_q(
            &[key_id_1],
            1,
            &[bad_sentinel],
            ii,
            iv,
            cid,
            0,
            "TEST",
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject SENTINEL with pubkey data");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_threshold_invalid_suite_q() {
        // Non-SENTINEL witness with unknown suite_id
        let kp1 = Mldsa87Keypair::generate().expect("kp1");
        let key_id_1 = sha3_256(&kp1.pubkey_bytes());
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut witness = sign_witness(&kp1, &tx, ii, iv, cid);
        witness.suite_id = 0xFE; // unknown suite
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_threshold_sig_spend_q(
            &[key_id_1],
            1,
            &[witness],
            ii,
            iv,
            cid,
            0,
            "TEST",
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject unknown suite");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn validate_threshold_non_canonical_sig_q() {
        // Witness with correct suite but wrong pubkey length
        let kp1 = Mldsa87Keypair::generate().expect("kp1");
        let key_id_1 = sha3_256(&kp1.pubkey_bytes());
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut witness = sign_witness(&kp1, &tx, ii, iv, cid);
        witness.pubkey = vec![0u8; 10]; // non-canonical length
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_threshold_sig_spend_q(
            &[key_id_1],
            1,
            &[witness],
            ii,
            iv,
            cid,
            0,
            "TEST",
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-canonical lengths");
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn validate_threshold_multiple_signers_all_required_q() {
        // threshold=2 but only 1 valid signer → must fail
        let kp1 = Mldsa87Keypair::generate().expect("kp1");
        let kp2 = Mldsa87Keypair::generate().expect("kp2");
        let key_id_1 = sha3_256(&kp1.pubkey_bytes());
        let key_id_2 = sha3_256(&kp2.pubkey_bytes());
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness1 = sign_witness(&kp1, &tx, ii, iv, cid);
        let sentinel = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: Vec::new(),
            signature: Vec::new(),
        };
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_threshold_sig_spend_q(
            &[key_id_1, key_id_2],
            2,                     // threshold=2
            &[witness1, sentinel], // only 1 signer
            ii,
            iv,
            cid,
            0,
            "TEST",
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject: insufficient signers");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert!(queue.is_empty(), "threshold failure must roll back queue");
    }

    // P2PK Error Path Tests (3)

    #[test]
    fn validate_p2pk_suite_not_in_native_q() {
        let kp = Mldsa87Keypair::generate().expect("kp");
        let pubkey = kp.pubkey_bytes();
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut witness = sign_witness(&kp, &tx, ii, iv, cid);
        witness.suite_id = 0xFE; // unknown suite
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_p2pk_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-native suite");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn validate_p2pk_non_canonical_sig_q() {
        let kp = Mldsa87Keypair::generate().expect("kp");
        let pubkey = kp.pubkey_bytes();
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(&pubkey),
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut witness = sign_witness(&kp, &tx, ii, iv, cid);
        witness.pubkey = vec![0u8; 10]; // non-canonical pubkey length
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_p2pk_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-canonical");
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn validate_p2pk_covenant_data_invalid_q() {
        let kp = Mldsa87Keypair::generate().expect("kp");
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: vec![0u8; 5], // wrong covenant data length
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&kp, &tx, ii, iv, cid);
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_p2pk_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject invalid covenant data");
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    // Stealth Error Path Tests (4)

    #[test]
    fn validate_stealth_invalid_suite_q() {
        let kp = Mldsa87Keypair::generate().expect("kp");
        let one_time_key_id = sha3_256(&kp.pubkey_bytes());
        let entry = make_stealth_entry(one_time_key_id);
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut witness = sign_witness(&kp, &tx, ii, iv, cid);
        witness.suite_id = 0xFE; // unknown suite
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_stealth_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-native suite");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    }

    #[test]
    fn validate_stealth_bad_covenant_data_q() {
        let kp = Mldsa87Keypair::generate().expect("kp");
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_STEALTH,
            covenant_data: vec![0u8; 10], // wrong length (not 1600)
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&kp, &tx, ii, iv, cid);
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_stealth_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject bad covenant data");
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn validate_stealth_non_canonical_sig_q() {
        let kp = Mldsa87Keypair::generate().expect("kp");
        let one_time_key_id = sha3_256(&kp.pubkey_bytes());
        let entry = make_stealth_entry(one_time_key_id);
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut witness = sign_witness(&kp, &tx, ii, iv, cid);
        witness.pubkey = vec![0u8; 10]; // non-canonical length
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_stealth_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject non-canonical");
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn validate_stealth_key_binding_mismatch_q() {
        // Valid witness but pubkey hash doesn't match one_time_key_id in covenant
        let kp = Mldsa87Keypair::generate().expect("kp");
        let wrong_key_id = [0xCC; 32]; // doesn't match sha3_256(kp.pubkey_bytes())
        let entry = make_stealth_entry(wrong_key_id);
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&kp, &tx, ii, iv, cid);
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_stealth_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject key binding mismatch");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    // Queue Concurrency Tests (2)

    #[test]
    fn parallel_stress_valid_sigs_q() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let mut queue = SigCheckQueue::new(4);
        for i in 0..16u8 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            let sig = keypair.sign_digest32(digest).expect("sign");
            queue
                .push(
                    SUITE_ID_ML_DSA_87,
                    &keypair.pubkey_bytes(),
                    &sig,
                    digest,
                    TxError::new(ErrorCode::TxErrSigInvalid, "parallel"),
                )
                .expect("push");
        }
        queue.flush().expect("parallel flush must succeed");
        assert!(queue.is_empty());
    }

    #[test]
    fn concurrent_flush_safety_q() {
        // Flush after mixed valid/invalid ensures deterministic error from first failure
        let kp_good = Mldsa87Keypair::generate().expect("good kp");
        let kp_bad = Mldsa87Keypair::generate().expect("bad kp");
        let mut queue = SigCheckQueue::new(2);
        let digest = [0x99; 32];
        let good_sig = kp_good.sign_digest32(digest).expect("sign");
        let bad_sig = kp_bad.sign_digest32(digest).expect("sign");
        // First: valid
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &kp_good.pubkey_bytes(),
                &good_sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "good"),
            )
            .expect("push good");
        // Second: invalid (signed by kp_bad, verified against kp_good's pubkey)
        queue
            .push(
                SUITE_ID_ML_DSA_87,
                &kp_good.pubkey_bytes(),
                &bad_sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "bad-cross"),
            )
            .expect("push bad");
        let err = queue.flush().expect_err("mixed flush must fail");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    // Extended error path tests (4)

    #[test]
    fn validate_htlc_extended_payload_validation_q() {
        // Claim payload declares preimage length but actual data doesn't match
        let (entry, mut path_item, sig_item, tx, ii, iv, cid, reg) = htlc_claim_fixture();
        // Build payload with declared length=32 but only 3 bytes of payload data total
        let mut bad_payload = vec![0x00]; // claim path
        bad_payload.extend_from_slice(&32u16.to_le_bytes()); // declares 32 bytes
                                                             // but we only have the 3-byte header, no actual preimage data → length mismatch
        path_item.signature = bad_payload;
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            1,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject payload length mismatch");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_htlc_refund_extended_safety_q() {
        // Refund path with extra bytes in payload (should be exactly 1 byte)
        let claim_kp = Mldsa87Keypair::generate().expect("claim kp");
        let refund_kp = Mldsa87Keypair::generate().expect("refund kp");
        let claim_key_id = sha3_256(&claim_kp.pubkey_bytes());
        let refund_key_id = sha3_256(&refund_kp.pubkey_bytes());
        let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
        cov.extend_from_slice(&sha3_256(b"refund-extended-test"));
        cov.push(LOCK_MODE_HEIGHT);
        cov.extend_from_slice(&1u64.to_le_bytes());
        cov.extend_from_slice(&claim_key_id);
        cov.extend_from_slice(&refund_key_id);
        let entry = UtxoEntry {
            value: 1000,
            covenant_type: COV_TYPE_HTLC,
            covenant_data: cov,
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let sig_item = sign_witness(&refund_kp, &tx, ii, iv, cid);
        let path_item = WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: refund_key_id.to_vec(),
            signature: vec![0x01, 0x00], // 2 bytes instead of 1
        };
        let reg = SuiteRegistry::default_registry();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_htlc_spend_q(
            &entry,
            &path_item,
            &sig_item,
            ii,
            iv,
            cid,
            100,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject refund payload with extra bytes");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn validate_p2pk_extended_validation_q() {
        // P2PK covenant_data has correct length but wrong suite_id byte
        let kp = Mldsa87Keypair::generate().expect("kp");
        let pubkey = kp.pubkey_bytes();
        let mut cov = p2pk_covenant_data_for_pubkey(&pubkey);
        cov[0] = 0xFE; // wrong suite_id prefix
        let entry = UtxoEntry {
            value: 100,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: cov,
            creation_height: 0,
            created_by_coinbase: false,
        };
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&kp, &tx, ii, iv, cid);
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        let err = validate_p2pk_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect_err("must reject covenant suite mismatch");
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn validate_stealth_extended_safety_q() {
        // Stealth covenant data with exact right length but
        // embedded ciphertext is zeroed — key binding still must match
        let kp = Mldsa87Keypair::generate().expect("kp");
        let one_time_key_id = sha3_256(&kp.pubkey_bytes());
        let entry = make_stealth_entry(one_time_key_id);
        let (tx, ii, iv, cid) = test_tx_context();
        let mut cache = SighashV1PrehashCache::new(&tx).expect("cache");
        let witness = sign_witness(&kp, &tx, ii, iv, cid);
        let reg = SuiteRegistry::default_registry();
        let mut queue = SigCheckQueue::new(1).with_registry(&reg);
        // This should SUCCEED (key binding matches)
        validate_stealth_spend_q(
            &entry,
            &witness,
            ii,
            iv,
            cid,
            0,
            &mut cache,
            Some(&mut queue),
            None,
            Some(&reg),
        )
        .expect("stealth with zeroed ciphertext must pass validation");
        assert_eq!(queue.len(), 1);
        queue.flush().expect("flush");
    }
}
