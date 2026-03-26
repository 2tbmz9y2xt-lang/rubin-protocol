use crate::error::{ErrorCode, TxError};
use crate::suite_registry::SuiteRegistry;
use crate::verify_sig_openssl::{verify_sig, verify_sig_with_registry};
use std::collections::VecDeque;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SigCheckTask {
    suite_id: u8,
    pubkey: Vec<u8>,
    sig: Vec<u8>,
    digest: [u8; 32],
    err_on_fail: TxError,
}

/// SigCheckQueue collects deferred signature verification tasks during
/// sequential transaction validation. When flushed, it verifies all collected
/// signatures in parallel and returns the first error by submission order.
///
/// When no caller wires this queue into block validation, the sequential path
/// still verifies inline. Callers that do use the queue must flush it before
/// accepting a block; `assert_flushed` is the defensive postcondition for that.
#[derive(Debug, Default)]
pub struct SigCheckQueue {
    tasks: Vec<SigCheckTask>,
    workers: usize,
    registry: Option<SuiteRegistry>,
    panics: Arc<AtomicU64>,
}

impl SigCheckQueue {
    pub fn new(workers: usize) -> Self {
        Self {
            tasks: Vec::new(),
            workers,
            registry: None,
            panics: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_registry(mut self, registry: &SuiteRegistry) -> Self {
        self.registry = Some(registry.clone());
        self
    }

    pub(crate) fn push(
        &mut self,
        suite_id: u8,
        pubkey: &[u8],
        sig: &[u8],
        digest: [u8; 32],
        err_on_fail: TxError,
    ) {
        self.tasks.push(SigCheckTask {
            suite_id,
            pubkey: pubkey.to_vec(),
            sig: sig.to_vec(),
            digest,
            err_on_fail,
        });
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub fn assert_flushed(&self) -> Result<(), TxError> {
        if self.tasks.is_empty() {
            return Ok(());
        }
        Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "SigCheckQueue has unflushed tasks",
        ))
    }

    pub fn flush(&mut self) -> Result<(), TxError> {
        if self.tasks.is_empty() {
            return Ok(());
        }

        let tasks = std::mem::take(&mut self.tasks);
        if tasks.len() == 1 {
            return verify_queued_task(
                tasks.into_iter().next().expect("single task"),
                self.registry.as_ref(),
            );
        }

        let workers = normalized_worker_count(self.workers, tasks.len());
        let registry = self.registry.clone();
        let panics = Arc::clone(&self.panics);
        let any_failed = Arc::new(AtomicBool::new(false));
        let queue = Mutex::new(tasks.into_iter().enumerate().collect::<VecDeque<_>>());
        let results = (0..workers.max(1))
            .map(|_| Vec::<(usize, TxError)>::new())
            .collect::<Vec<_>>();
        let results = Arc::new(Mutex::new(results));

        thread::scope(|scope| {
            for worker_id in 0..workers {
                let any_failed = Arc::clone(&any_failed);
                let panics = Arc::clone(&panics);
                let registry = registry.clone();
                let results = Arc::clone(&results);
                let queue = &queue;
                scope.spawn(move || {
                    let mut current_idx = None;
                    let worker_run = || loop {
                        let next = {
                            let mut guard = lock_recover(queue);
                            guard.pop_front()
                        };
                        let Some((idx, task)) = next else {
                            break;
                        };
                        current_idx = Some(idx);
                        if any_failed.load(Ordering::SeqCst) {
                            continue;
                        }
                        if let Err(err) = verify_queued_task(task, registry.as_ref()) {
                            any_failed.store(true, Ordering::SeqCst);
                            lock_recover(&results)[worker_id].push((idx, err));
                        }
                    };

                    if panic::catch_unwind(AssertUnwindSafe(worker_run)).is_err() {
                        if let Some(idx) = current_idx {
                            panics.fetch_add(1, Ordering::SeqCst);
                            any_failed.store(true, Ordering::SeqCst);
                            lock_recover(&results)[worker_id].push((
                                idx,
                                TxError::new(
                                    ErrorCode::TxErrSigInvalid,
                                    "signature worker panic (fail-closed)",
                                ),
                            ));
                        }
                    }
                });
            }
        });

        let mut first_error: Option<(usize, TxError)> = None;
        for worker_results in lock_recover(&results).iter() {
            for (idx, err) in worker_results {
                match &first_error {
                    Some((best_idx, _)) if idx >= best_idx => {}
                    _ => first_error = Some((*idx, err.clone())),
                }
            }
        }
        if let Some((_, err)) = first_error {
            return Err(err);
        }
        Ok(())
    }

    pub fn panics(&self) -> u64 {
        self.panics.load(Ordering::SeqCst)
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
        queue.push(suite_id, pubkey, crypto_sig, digest, err_on_fail);
        return Ok(());
    }

    let ok = verify_sig_with_registry(suite_id, pubkey, crypto_sig, &digest, Some(registry))?;
    if !ok {
        return Err(err_on_fail);
    }
    Ok(())
}

fn verify_queued_task(task: SigCheckTask, registry: Option<&SuiteRegistry>) -> Result<(), TxError> {
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
    Ok(())
}

fn normalized_worker_count(max_workers: usize, task_count: usize) -> usize {
    let mut workers = max_workers;
    if workers == 0 {
        workers = thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1)
            .max(1);
    }
    workers.min(task_count).max(1)
}

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compactsize::encode_compact_size;
    use crate::constants::{
        COV_TYPE_EXT, COV_TYPE_HTLC, COV_TYPE_P2PK, COV_TYPE_STEALTH, LOCK_MODE_HEIGHT,
        MAX_HTLC_COVENANT_DATA, MAX_STEALTH_COVENANT_DATA, ML_KEM_1024_CT_BYTES, SIGHASH_ALL,
        SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
    };
    use crate::core_ext::{
        parse_core_ext_covenant_data, validate_core_ext_spend_with_cache_and_suite_context_q,
        CoreExtActiveProfile, CoreExtProfiles, CoreExtVerificationBinding,
    };
    use crate::hash::sha3_256;
    use crate::htlc::parse_htlc_covenant_data;
    use crate::htlc::validate_htlc_spend_q;
    use crate::spend_verify::{validate_p2pk_spend_q, validate_threshold_sig_spend_q};
    use crate::stealth::parse_stealth_covenant_data;
    use crate::stealth::validate_stealth_spend_q;
    use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
    use crate::tx_helpers::p2pk_covenant_data_for_pubkey;
    use crate::utxo_basic::UtxoEntry;
    use crate::verify_sig_openssl::Mldsa87Keypair;
    use crate::{sighash_v1_digest_with_cache, SighashV1PrehashCache};

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
        queue.push(
            SUITE_ID_ML_DSA_87,
            &keypair_a.pubkey_bytes(),
            &bad_sig_a,
            digest_a,
            TxError::new(ErrorCode::TxErrSigInvalid, "first failure"),
        );
        queue.push(
            SUITE_ID_ML_DSA_87,
            &keypair_b.pubkey_bytes(),
            &bad_sig_b,
            digest_b,
            TxError::new(ErrorCode::TxErrSigInvalid, "second failure"),
        );

        let err = queue.flush().expect_err("flush must fail");
        assert_eq!(
            err,
            TxError::new(ErrorCode::TxErrSigInvalid, "first failure")
        );
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn sig_check_queue_is_reusable_after_flush() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0x33; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");

        let mut queue = SigCheckQueue::new(1);
        queue.push(
            SUITE_ID_ML_DSA_87,
            &keypair.pubkey_bytes(),
            &sig,
            digest,
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        );
        queue.flush().expect("first flush");
        queue.assert_flushed().expect("queue empty");

        queue.push(
            SUITE_ID_ML_DSA_87,
            &keypair.pubkey_bytes(),
            &sig,
            digest,
            TxError::new(ErrorCode::TxErrSigInvalid, "sig invalid"),
        );
        queue.flush().expect("second flush");
        queue.assert_flushed().expect("queue empty again");
    }

    #[test]
    fn sig_check_queue_zero_value_flush_fails_closed() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");

        let mut queue = SigCheckQueue::default();
        for i in 0..4u8 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            let sig = keypair.sign_digest32(digest).expect("sign");
            queue.push(
                SUITE_ID_ML_DSA_87,
                &keypair.pubkey_bytes(),
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "zero-value"),
            );
        }
        queue.flush().expect("valid zero-value flush");

        for i in 0..4u8 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            let sig = keypair.sign_digest32(digest).expect("sign");
            digest[0] ^= 0xff;
            queue.push(
                SUITE_ID_ML_DSA_87,
                &keypair.pubkey_bytes(),
                &sig,
                digest,
                TxError::new(ErrorCode::TxErrSigInvalid, "zero-value-invalid"),
            );
        }
        assert!(queue.flush().is_err(), "invalid zero-value flush must fail");
    }

    #[test]
    fn sig_check_queue_assert_flushed_unflushed() {
        let keypair = Mldsa87Keypair::generate().expect("keypair");
        let digest = [0x44; 32];
        let sig = keypair.sign_digest32(digest).expect("sign");

        let mut queue = SigCheckQueue::new(1);
        queue.push(
            SUITE_ID_ML_DSA_87,
            &keypair.pubkey_bytes(),
            &sig,
            digest,
            TxError::new(ErrorCode::TxErrSigInvalid, "test"),
        );

        let err = queue
            .assert_flushed()
            .expect_err("must detect unflushed queue");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn sig_check_queue_single_bad_suite_error() {
        let mut queue = SigCheckQueue::new(1);
        queue.push(
            0xfe,
            b"fake-pubkey",
            b"fake-sig",
            [0u8; 32],
            TxError::new(ErrorCode::TxErrSigInvalid, "test"),
        );
        assert!(queue.flush().is_err(), "bad suite id must fail");
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
        queue.assert_flushed().expect("empty");
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
}
