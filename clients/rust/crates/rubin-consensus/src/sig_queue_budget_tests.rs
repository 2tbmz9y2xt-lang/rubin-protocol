use super::*;
use crate::constants::{
    MAX_BLOCK_WEIGHT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87,
    VERIFY_COST_ML_DSA_87,
};
use crate::suite_registry::{SuiteParams, SuiteRegistry};
use std::collections::BTreeMap;

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
    let err = ensure_task_budget(limit, None).expect_err("task budget boundary must fail closed");
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
    let err = sigcheck_task_bytes(usize::MAX, 1).expect_err("footprint overflow must fail closed");
    assert_eq!(err.code, ErrorCode::TxErrWitnessOverflow);
}

#[test]
fn sigcheck_task_bytes_is_architecture_independent() {
    let bytes = sigcheck_task_bytes(10, 20).expect("accounting");
    assert_eq!(bytes, SIGCHECK_TASK_FIXED_OVERHEAD_BYTES + 30);
}
