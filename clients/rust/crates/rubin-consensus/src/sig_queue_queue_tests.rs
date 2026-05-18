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
