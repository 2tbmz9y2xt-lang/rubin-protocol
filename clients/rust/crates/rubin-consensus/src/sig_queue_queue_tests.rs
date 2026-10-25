use super::*;
use crate::constants::SUITE_ID_ML_DSA_87;
use crate::sig_cache::SigCache;
use crate::verify_sig_openssl::Mldsa87Keypair;

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
fn rub721_consuming_suffix() {
    let kp = Mldsa87Keypair::generate().expect("RUB-721 requires native ML-DSA");
    let registry = SuiteRegistry::default_registry();
    let prefix_digest = [0x71; 32];
    let prefix_sig = kp.sign_digest32(prefix_digest).expect("prefix signature");
    for bound in [false, true] {
        for prefix_count in [0, 1] {
            // (task count, failing index, verifier error, expected evaluations)
            for case in [
                (0, None, false, 0),
                (1, None, false, 1),
                (3, None, false, 3),
                (1, Some(0), false, 1),
                (3, Some(0), false, 1),
                (3, Some(1), false, 2),
                (3, Some(0), true, 1),
            ] {
                rub721_suffix_case(&kp, &registry, &prefix_sig, bound, prefix_count, case);
            }
        }
    }
}

fn rub721_prefix_queue(
    kp: &Mldsa87Keypair,
    registry: &SuiteRegistry,
    prefix_sig: &[u8],
    bound: bool,
    prefix_count: usize,
) -> (SigCheckQueue, SigCache) {
    let cache = SigCache::new(16);
    let mut queue = SigCheckQueue::new(4).with_cache(cache.clone());
    if bound {
        queue = queue.with_registry(registry);
    }
    for _ in 0..prefix_count {
        queue
            .push(
                1,
                &kp.pubkey_bytes(),
                prefix_sig,
                [0x71; 32],
                TxError::new(ErrorCode::TxErrSigInvalid, "retained prefix"),
            )
            .unwrap();
    }
    (queue, cache)
}

fn rub721_enqueue_suffix(
    kp: &Mldsa87Keypair,
    registry: &SuiteRegistry,
    queue: &mut SigCheckQueue,
    count: usize,
    bad: Option<usize>,
    verifier_error: bool,
) {
    for index in 0..count {
        let signed_digest = [0x80 + index as u8; 32];
        let mut pubkey = kp.pubkey_bytes();
        let mut signature = kp.sign_digest32(signed_digest).unwrap();
        let digest = if bad.is_some_and(|first| index >= first) {
            [0xa0 + index as u8; 32]
        } else {
            signed_digest
        };
        let suite = if verifier_error && index == 0 {
            0xfe
        } else {
            1
        };
        let message = if index == 0 {
            "suffix zero"
        } else {
            "suffix later"
        };
        queue_or_verify_signature(
            suite,
            &pubkey,
            &signature,
            digest,
            registry,
            &mut Some(&mut *queue),
            TxError::new(ErrorCode::TxErrSigInvalid, message),
        )
        .unwrap();
        pubkey.fill(0);
        signature.fill(0);
    }
}

fn rub721_suffix_case(
    kp: &Mldsa87Keypair,
    registry: &SuiteRegistry,
    prefix_sig: &[u8],
    bound: bool,
    prefix_count: usize,
    (count, bad, verifier_error, evaluations): (usize, Option<usize>, bool, u64),
) {
    let (mut queue, cache) = rub721_prefix_queue(kp, registry, prefix_sig, bound, prefix_count);
    let mark = queue.mark();
    let prefix = queue.tasks.clone();
    let entry_registry = queue.registry.clone();
    rub721_enqueue_suffix(kp, registry, &mut queue, count, bad, verifier_error);
    let expected = match (bad, verifier_error) {
        (_, true) => Err(TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "verify_sig: unsupported suite_id",
        )),
        (Some(0), false) => Err(TxError::new(ErrorCode::TxErrSigInvalid, "suffix zero")),
        (Some(_), false) => Err(TxError::new(ErrorCode::TxErrSigInvalid, "suffix later")),
        (None, false) => Ok(()),
    };
    assert_eq!(queue.settle_suffix(mark), expected);
    assert_eq!(queue.mark(), mark);
    assert_eq!(queue.tasks, prefix);
    assert_eq!(queue.registry, entry_registry);
    assert_eq!((cache.hits(), cache.misses()), (0, evaluations));
    let observed = (cache.len(), cache.hits(), cache.misses());
    queue.settle_suffix(mark).unwrap();
    assert_eq!((cache.len(), cache.hits(), cache.misses()), observed);
    rub721_valid_sibling(
        kp,
        registry,
        prefix_sig,
        &mut queue,
        &cache,
        evaluations as usize - usize::from(bad.is_some()) + 1,
    );
}

fn rub721_valid_sibling(
    kp: &Mldsa87Keypair,
    registry: &SuiteRegistry,
    prefix_sig: &[u8],
    queue: &mut SigCheckQueue,
    cache: &SigCache,
    expected_cache_len: usize,
) {
    queue_or_verify_signature(
        1,
        &kp.pubkey_bytes(),
        prefix_sig,
        [0x71; 32],
        registry,
        &mut Some(&mut *queue),
        TxError::new(ErrorCode::TxErrSigInvalid, "next valid sibling"),
    )
    .unwrap();
    queue
        .flush()
        .expect("prefix and valid sibling remain usable");
    assert_eq!(queue.queued_bytes, 0);
    assert!(queue.tasks.is_empty());
    assert_eq!(cache.len(), expected_cache_len);
}

#[test]
fn rub721_consuming_suffix_budget_and_empty_binding() {
    let kp = Mldsa87Keypair::generate().expect("RUB-721 requires native ML-DSA");
    let registry = SuiteRegistry::default_registry();
    let digest = [0x72; 32];
    let task = SigCheckTask {
        suite_id: 1,
        pubkey: kp.pubkey_bytes(),
        sig: kp.sign_digest32(digest).unwrap(),
        digest,
        err_on_fail: TxError::new(ErrorCode::TxErrSigInvalid, "budget task"),
    };
    let mut queue = SigCheckQueue::new(1);
    rub721_empty_binding(&mut queue, &task, &registry);
    rub721_byte_budget(&mut queue, &task);
    rub721_task_budget(&mut queue, &task);
}

fn rub721_empty_binding(queue: &mut SigCheckQueue, task: &SigCheckTask, registry: &SuiteRegistry) {
    let unbound = queue.mark();
    queue.queued_bytes = MAX_SIGCHECK_QUEUE_BYTES;
    assert_eq!(
        queue_or_verify_signature(
            1,
            &task.pubkey,
            &task.sig,
            task.digest,
            registry,
            &mut Some(&mut *queue),
            task.err_on_fail.clone(),
        )
        .unwrap_err(),
        TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "SigCheckQueue queued-byte budget exceeded"
        )
    );
    assert!(queue.registry.is_some());
    queue.settle_suffix(unbound).unwrap();
    assert_eq!(
        queue.mark(),
        unbound,
        "empty suffix restores failed-push binding"
    );
}

fn rub721_byte_budget(queue: &mut SigCheckQueue, task: &SigCheckTask) {
    let SigCheckTask {
        pubkey,
        sig,
        digest,
        err_on_fail,
        ..
    } = task;
    let task_bytes = sigcheck_task_bytes(task.pubkey.len(), task.sig.len()).unwrap();
    queue.queued_bytes = MAX_SIGCHECK_QUEUE_BYTES - task_bytes;
    let byte_mark = queue.mark();
    queue
        .push(1, pubkey, sig, *digest, err_on_fail.clone())
        .unwrap();
    assert_eq!(queue.queued_bytes, MAX_SIGCHECK_QUEUE_BYTES);
    assert_eq!(
        queue
            .push(1, pubkey, sig, *digest, err_on_fail.clone())
            .unwrap_err(),
        TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "SigCheckQueue queued-byte budget exceeded"
        )
    );
    queue.settle_suffix(byte_mark).unwrap();
    assert_eq!(queue.mark(), byte_mark);
    queue
        .push(1, pubkey, sig, *digest, err_on_fail.clone())
        .unwrap();
    queue.flush().unwrap();
}

fn rub721_task_budget(queue: &mut SigCheckQueue, task: &SigCheckTask) {
    let SigCheckTask {
        pubkey,
        sig,
        digest,
        err_on_fail,
        ..
    } = task;
    queue
        .push(1, pubkey, sig, *digest, err_on_fail.clone())
        .unwrap();
    let prefix = queue.tasks.clone();
    let mark = queue.mark();
    let cap = max_sigcheck_queue_tasks(queue.registry.as_ref()).unwrap();
    while queue.len() < cap {
        queue
            .push(0xfe, &[], &[], *digest, err_on_fail.clone())
            .unwrap();
    }
    assert_eq!(
        queue
            .push(1, pubkey, sig, *digest, err_on_fail.clone())
            .unwrap_err(),
        TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "SigCheckQueue task budget exceeded"
        )
    );
    assert_eq!(
        queue.settle_suffix(mark).unwrap_err(),
        TxError::new(
            ErrorCode::TxErrSigAlgInvalid,
            "verify_sig: unsupported suite_id"
        )
    );
    assert_eq!(queue.mark(), mark);
    assert_eq!(queue.tasks, prefix);
    queue
        .push(1, pubkey, sig, *digest, err_on_fail.clone())
        .unwrap();
    queue.flush().unwrap();
}
