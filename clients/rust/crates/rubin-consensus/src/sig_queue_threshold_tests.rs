use super::test_support::{sign_witness, test_tx_context};
use super::*;
use crate::constants::SUITE_ID_SENTINEL;
use crate::hash::sha3_256;
use crate::spend_verify::validate_threshold_sig_spend_q;
use crate::suite_registry::SuiteRegistry;
use crate::tx::WitnessItem;
use crate::verify_sig_openssl::Mldsa87Keypair;
use crate::SighashV1PrehashCache;

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
    assert_eq!(err.msg, "witness slot assignment mismatch");
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

#[test]
fn rub721_threshold_order() {
    let fixture = rub721_threshold_fixture();
    for context in ["CORE_MULTISIG", "CORE_VAULT"] {
        for first_valid in [false, true] {
            for variant in 0..9 {
                rub721_threshold_case(&fixture, context, first_valid, variant);
            }
        }
    }
}

struct Rub721Overlap;

impl crate::suite_registry::RotationProvider for Rub721Overlap {
    fn native_create_suites(&self, _: u64) -> crate::suite_registry::NativeSuiteSet {
        crate::suite_registry::NativeSuiteSet::new(&[1, 2])
    }

    fn native_spend_suites(&self, _: u64) -> crate::suite_registry::NativeSuiteSet {
        crate::suite_registry::NativeSuiteSet::new(&[1, 2])
    }
}

struct Rub721ThresholdFixture {
    kp: Mldsa87Keypair,
    keys: [[u8; 32]; 2],
    good: WitnessItem,
    second_good: WitnessItem,
    bad: WitnessItem,
    tx: crate::tx::Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    registry: SuiteRegistry,
}

fn rub721_threshold_fixture() -> Rub721ThresholdFixture {
    let kp = Mldsa87Keypair::generate().expect("RUB-721 requires native ML-DSA");
    let second_kp = Mldsa87Keypair::generate().expect("RUB-721 requires native ML-DSA");
    let key = sha3_256(&kp.pubkey_bytes());
    let second_key = sha3_256(&second_kp.pubkey_bytes());
    let (tx, ii, iv, cid) = test_tx_context();
    let mut wrong_tx = tx.clone();
    wrong_tx.tx_nonce += 1;
    let good = sign_witness(&kp, &tx, ii, iv, cid);
    let second_good = sign_witness(&second_kp, &tx, ii, iv, cid);
    let bad = sign_witness(&kp, &wrong_tx, ii, iv, cid);
    Rub721ThresholdFixture {
        kp,
        keys: [key, second_key],
        good,
        second_good,
        bad,
        tx,
        input_index: ii,
        input_value: iv,
        chain_id: cid,
        registry: SuiteRegistry::default_registry(),
    }
}

fn rub721_threshold_messages(context: &str) -> [&'static str; 5] {
    match context {
        "CORE_MULTISIG" => [
            "CORE_MULTISIG signature invalid",
            "CORE_MULTISIG suite not in native spend set",
            "CORE_MULTISIG suite not registered",
            "CORE_MULTISIG key binding mismatch",
            "CORE_MULTISIG threshold not met",
        ],
        _ => [
            "CORE_VAULT signature invalid",
            "CORE_VAULT suite not in native spend set",
            "CORE_VAULT suite not registered",
            "CORE_VAULT key binding mismatch",
            "CORE_VAULT threshold not met",
        ],
    }
}

fn rub721_later_key_failure(
    variant: usize,
    later: &mut WitnessItem,
    key: &mut [u8; 32],
    messages: [&'static str; 5],
) -> TxError {
    let [_, suite, registered, binding, threshold_message] = messages;
    match variant {
        0 => {
            later.suite_id = 0xfe;
            TxError::new(ErrorCode::TxErrSigAlgInvalid, suite)
        }
        1 => {
            later.suite_id = 2;
            TxError::new(ErrorCode::TxErrSigAlgInvalid, registered)
        }
        2 => {
            *key = [0x55; 32];
            TxError::new(ErrorCode::TxErrSigInvalid, binding)
        }
        3 => {
            *later.signature.last_mut().unwrap() = 0;
            TxError::new(ErrorCode::TxErrSighashTypeInvalid, "invalid sighash_type")
        }
        _ => rub721_later_witness_failure(variant, later, threshold_message),
    }
}

fn rub721_later_witness_failure(
    variant: usize,
    later: &mut WitnessItem,
    threshold_message: &'static str,
) -> TxError {
    match variant {
        4 => {
            later.pubkey.pop();
            TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "non-canonical witness item lengths",
            )
        }
        5 => {
            later.signature.pop();
            TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "non-canonical witness item lengths",
            )
        }
        6 => {
            *later = WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: vec![1],
                signature: vec![],
            };
            TxError::new(ErrorCode::TxErrParse, "SENTINEL witness must be keyless")
        }
        7 => {
            *later = WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: vec![],
                signature: vec![1],
            };
            TxError::new(ErrorCode::TxErrParse, "SENTINEL witness must be keyless")
        }
        _ => {
            *later = WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: vec![],
                signature: vec![],
            };
            TxError::new(ErrorCode::TxErrSigInvalid, threshold_message)
        }
    }
}

fn rub721_threshold_prefix(fixture: &Rub721ThresholdFixture) -> SigCheckQueue {
    let mut queue = SigCheckQueue::new(2).with_registry(&fixture.registry);
    let prefix_digest = [0x73; 32];
    queue
        .push(
            1,
            &fixture.kp.pubkey_bytes(),
            &fixture.kp.sign_digest32(prefix_digest).unwrap(),
            prefix_digest,
            TxError::new(ErrorCode::TxErrSigInvalid, "prefix"),
        )
        .unwrap();
    queue
}

fn rub721_threshold_case(
    fixture: &Rub721ThresholdFixture,
    context: &'static str,
    first_valid: bool,
    variant: usize,
) {
    let messages = rub721_threshold_messages(context);
    let mut keys = fixture.keys;
    let mut later = fixture.second_good.clone();
    let expected = rub721_later_key_failure(variant, &mut later, &mut keys[1], messages);
    let mut queue = rub721_threshold_prefix(fixture);
    let mark = queue.mark();
    let prefix = queue.tasks.clone();
    let mut cache = SighashV1PrehashCache::new(&fixture.tx).unwrap();
    let first = if first_valid {
        fixture.good.clone()
    } else {
        fixture.bad.clone()
    };
    let error = validate_threshold_sig_spend_q(
        &keys,
        2,
        &[first, later],
        fixture.input_index,
        fixture.input_value,
        fixture.chain_id,
        0,
        context,
        &mut cache,
        Some(&mut queue),
        Some(&Rub721Overlap),
        Some(&fixture.registry),
    )
    .unwrap_err();
    assert_eq!(
        error,
        if first_valid {
            expected
        } else {
            TxError::new(ErrorCode::TxErrSigInvalid, messages[0])
        },
        "{context} case {variant}, first_valid={first_valid}"
    );
    assert_eq!(queue.mark(), mark);
    assert_eq!(queue.tasks, prefix);
    rub721_next_threshold_helper(fixture, context, &mut queue, &mut cache, mark);
}

fn rub721_next_threshold_helper(
    fixture: &Rub721ThresholdFixture,
    context: &'static str,
    queue: &mut SigCheckQueue,
    cache: &mut SighashV1PrehashCache<'_>,
    mark: SigCheckQueueMark,
) {
    validate_threshold_sig_spend_q(
        &fixture.keys,
        2,
        &[fixture.good.clone(), fixture.second_good.clone()],
        fixture.input_index,
        fixture.input_value,
        fixture.chain_id,
        0,
        context,
        cache,
        Some(&mut *queue),
        Some(&Rub721Overlap),
        Some(&fixture.registry),
    )
    .unwrap();
    assert_eq!(queue.len(), mark.len + 2, "successful helper retains tasks");
    queue.flush().expect("prefix and next valid helper");
}
