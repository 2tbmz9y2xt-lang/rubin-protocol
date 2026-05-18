use super::*;
use crate::constants::{
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
};
use crate::suite_registry::{SuiteParams, SuiteRegistry};
use crate::verify_sig_openssl::Mldsa87Keypair;
use std::collections::BTreeMap;

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
