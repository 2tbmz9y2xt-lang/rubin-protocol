use std::sync::{Mutex, OnceLock};

use crate::constants::{
    COV_TYPE_HTLC, COV_TYPE_P2PK, COV_TYPE_STEALTH, LOCK_MODE_HEIGHT, LOCK_MODE_TIMESTAMP,
    MAX_HTLC_COVENANT_DATA, MAX_STEALTH_COVENANT_DATA, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
    ML_KEM_1024_CT_BYTES, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE,
    SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
};
use crate::error::ErrorCode;
use crate::featurebits::{
    featurebit_state_at_height_from_window_counts, FeatureBitDeployment, FeatureBitState,
};
use crate::htlc::{parse_htlc_covenant_data, validate_htlc_spend};
use crate::sighash::{is_valid_sighash_type, sighash_v1_digest_with_type};
use crate::spend_verify::{validate_p2pk_spend, validate_threshold_sig_spend};
use crate::stealth::{parse_stealth_covenant_data, validate_stealth_spend};
use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::{
    test_ensure_openssl_bootstrap_for_mode, test_openssl_check_sigalg_bad_alg,
    test_openssl_verify_sig_digest_oneshot_bad_alg,
    test_openssl_verify_sig_digest_oneshot_empty_input, test_set_env_if_empty, test_suite_alg_name,
    verify_sig,
};
use crate::wire_read::Reader;

fn dummy_chain_id() -> [u8; 32] {
    [0x11; 32]
}

fn base_tx() -> Tx {
    Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 7,
        inputs: vec![TxInput {
            prev_txid: [0x42; 32],
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
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    }
}

fn mldsa_pubkey(fill: u8) -> Vec<u8> {
    vec![fill; ML_DSA_87_PUBKEY_BYTES as usize]
}

fn mldsa_signature(fill: u8) -> Vec<u8> {
    let mut sig = vec![fill; ML_DSA_87_SIG_BYTES as usize];
    sig.push(SIGHASH_ALL);
    sig
}

fn p2pk_entry_for_pubkey(pubkey: &[u8]) -> UtxoEntry {
    let mut cov = vec![0u8; 33];
    cov[0] = SUITE_ID_ML_DSA_87;
    cov[1..33].copy_from_slice(&crate::hash::sha3_256(pubkey));
    UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov,
        creation_height: 0,
        created_by_coinbase: false,
    }
}

fn stealth_entry_for_pubkey(pubkey: &[u8]) -> UtxoEntry {
    let mut cov = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
    cov[ML_KEM_1024_CT_BYTES as usize..].copy_from_slice(&crate::hash::sha3_256(pubkey));
    UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_STEALTH,
        covenant_data: cov,
        creation_height: 0,
        created_by_coinbase: false,
    }
}

fn htlc_components(lock_mode: u8, lock_value: u64) -> ([u8; 32], [u8; 32], [u8; 32], Vec<u8>) {
    let preimage = [0x55; 32];
    let hash = crate::hash::sha3_256(&preimage);
    let claim_key_id = [0x11; 32];
    let refund_key_id = [0x22; 32];
    let mut cov = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
    cov.extend_from_slice(&hash);
    cov.push(lock_mode);
    cov.extend_from_slice(&lock_value.to_le_bytes());
    cov.extend_from_slice(&claim_key_id);
    cov.extend_from_slice(&refund_key_id);
    (claim_key_id, refund_key_id, preimage, cov)
}

fn htlc_entry(covenant_data: Vec<u8>) -> UtxoEntry {
    UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_HTLC,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    }
}

fn htlc_claim_selector(selector_key_id: [u8; 32], preimage: &[u8]) -> WitnessItem {
    let mut sig = vec![0x00];
    sig.extend_from_slice(&(preimage.len() as u16).to_le_bytes());
    sig.extend_from_slice(preimage);
    WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: selector_key_id.to_vec(),
        signature: sig,
    }
}

fn htlc_refund_selector(selector_key_id: [u8; 32]) -> WitnessItem {
    WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: selector_key_id.to_vec(),
        signature: vec![0x01],
    }
}

fn openssl_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn featurebits_strings_and_validation_errors() {
    assert_eq!(FeatureBitState::Defined.as_str(), "DEFINED");
    let bad = FeatureBitDeployment {
        name: String::new(),
        bit: 0,
        start_height: 0,
        timeout_height: 1,
    };
    assert!(featurebit_state_at_height_from_window_counts(&bad, 0, &[]).is_err());
}

#[test]
fn featurebits_window_requirements_and_defined_state() {
    let dep = FeatureBitDeployment {
        name: "x".to_string(),
        bit: 1,
        start_height: 100,
        timeout_height: 200,
    };
    let eval = featurebit_state_at_height_from_window_counts(&dep, 0, &[]).expect("eval");
    assert_eq!(eval.state, FeatureBitState::Defined);
    assert!(featurebit_state_at_height_from_window_counts(&dep, 2016, &[]).is_err());
}

#[test]
fn sighash_rejects_invalid_input_and_type() {
    let tx = base_tx();
    assert!(sighash_v1_digest_with_type(&tx, 1, 100, dummy_chain_id(), SIGHASH_ALL).is_err());
    assert!(sighash_v1_digest_with_type(&tx, 0, 100, dummy_chain_id(), 0x7f).is_err());
    assert!(is_valid_sighash_type(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY));
}

#[test]
fn sighash_modes_cover_anyonecanpay_none_and_single() {
    let mut tx = base_tx();
    assert!(sighash_v1_digest_with_type(
        &tx,
        0,
        100,
        dummy_chain_id(),
        SIGHASH_NONE | SIGHASH_ANYONECANPAY
    )
    .is_ok());
    tx.outputs.clear();
    assert!(sighash_v1_digest_with_type(&tx, 0, 100, dummy_chain_id(), SIGHASH_SINGLE).is_ok());
}

#[test]
fn reader_reads_sequential_values_and_offsets() {
    let mut r = Reader::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(r.read_u8().expect("u8"), 1);
    assert_eq!(r.read_u16_le().expect("u16"), 0x0302);
    assert_eq!(r.offset(), 3);
    assert_eq!(r.read_bytes(2).expect("bytes"), &[4, 5]);
}

#[test]
fn reader_reports_eof_for_each_read_shape() {
    let mut r = Reader::new(&[]);
    assert!(r.read_u8().is_err());
    let mut r = Reader::new(&[1]);
    assert!(r.read_u16_le().is_err());
    let mut r = Reader::new(&[1, 2, 3]);
    assert!(r.read_u32_le().is_err());
    let mut r = Reader::new(&[1, 2, 3, 4, 5, 6, 7]);
    assert!(r.read_u64_le().is_err());
    let mut r = Reader::new(&[1]);
    assert!(r.read_bytes(2).is_err());
}

#[test]
fn verify_sig_rejects_unsupported_suite_and_bad_lengths() {
    assert!(verify_sig(0xff, &[], &[], &[0u8; 32]).is_err());
    let ok = verify_sig(SUITE_ID_ML_DSA_87, &[0u8; 1], &[0u8; 1], &[0u8; 32]).expect("bad lengths");
    assert!(!ok);
}

#[test]
fn verify_sig_testability_wrappers_cover_bootstrap_helpers() {
    let _guard = openssl_env_lock().lock().expect("env lock");
    std::env::remove_var("RUBIN_TEST_ENV_COVERAGE");
    test_set_env_if_empty("RUBIN_TEST_ENV_COVERAGE", Some(" value ".to_string()));
    assert_eq!(
        std::env::var("RUBIN_TEST_ENV_COVERAGE").expect("env"),
        "value"
    );
    assert_eq!(
        test_suite_alg_name(SUITE_ID_ML_DSA_87).expect("alg"),
        "ML-DSA-87"
    );
    assert!(test_suite_alg_name(0xff).is_err());
    assert!(test_ensure_openssl_bootstrap_for_mode("off").is_ok());
    assert!(test_ensure_openssl_bootstrap_for_mode("garbage").is_err());
    assert!(test_openssl_check_sigalg_bad_alg().is_err());
    assert!(test_openssl_verify_sig_digest_oneshot_empty_input().is_err());
    assert!(test_openssl_verify_sig_digest_oneshot_bad_alg().is_err());
}

#[test]
fn parse_htlc_covenant_data_rejects_invalid_variants() {
    assert!(parse_htlc_covenant_data(&[]).is_err());
    let (_, _, _, mut cov) = htlc_components(9, 1);
    assert!(parse_htlc_covenant_data(&cov).is_err());
    cov = htlc_components(LOCK_MODE_HEIGHT, 0).3;
    assert!(parse_htlc_covenant_data(&cov).is_err());
    let (claim_key_id, refund_key_id, _, cov) = htlc_components(LOCK_MODE_HEIGHT, 5);
    let parsed = parse_htlc_covenant_data(&cov).expect("valid htlc parse");
    assert_eq!(parsed.claim_key_id, claim_key_id);
    assert_eq!(parsed.refund_key_id, refund_key_id);
}

#[test]
fn validate_htlc_spend_rejects_selector_shape_errors() {
    let (claim_key_id, _, _, cov) = htlc_components(LOCK_MODE_HEIGHT, 5);
    let entry = htlc_entry(cov);
    let path = WitnessItem {
        suite_id: 1,
        pubkey: vec![],
        signature: vec![],
    };
    let sig = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: mldsa_pubkey(1),
        signature: mldsa_signature(2),
    };
    let err = validate_htlc_spend(
        &entry,
        &path,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let path = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: claim_key_id.to_vec(),
        signature: vec![],
    };
    let err = validate_htlc_spend(
        &entry,
        &path,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let path = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![1],
        signature: vec![0],
    };
    let err = validate_htlc_spend(
        &entry,
        &path,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn validate_htlc_spend_rejects_claim_path_errors() {
    let (claim_key_id, _, preimage, cov) = htlc_components(LOCK_MODE_HEIGHT, 5);
    let entry = htlc_entry(cov);
    let short = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: claim_key_id.to_vec(),
        signature: vec![0x00, 0x01],
    };
    let sig = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: mldsa_pubkey(1),
        signature: mldsa_signature(2),
    };
    let err = validate_htlc_spend(
        &entry,
        &short,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let tiny_preimage = htlc_claim_selector(claim_key_id, &[1; 8]);
    let err = validate_htlc_spend(
        &entry,
        &tiny_preimage,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let overflow_preimage = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: claim_key_id.to_vec(),
        signature: {
            let mut s = vec![0x00];
            s.extend_from_slice(&257u16.to_le_bytes());
            s.extend_from_slice(&vec![0u8; 257]);
            s
        },
    };
    let err = validate_htlc_spend(
        &entry,
        &overflow_preimage,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let mut bad_preimage = preimage;
    bad_preimage[0] ^= 0xff;
    let path = htlc_claim_selector(claim_key_id, &bad_preimage);
    let err = validate_htlc_spend(
        &entry,
        &path,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);

    let wrong_selector = htlc_claim_selector([0x33; 32], &preimage);
    let err = validate_htlc_spend(
        &entry,
        &wrong_selector,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn validate_htlc_spend_rejects_refund_and_signature_errors() {
    let (_, refund_key_id, _, cov) = htlc_components(LOCK_MODE_TIMESTAMP, 50);
    let entry = htlc_entry(cov);
    let path = htlc_refund_selector(refund_key_id);
    let bad_sig = WitnessItem {
        suite_id: 0xff,
        pubkey: vec![],
        signature: vec![],
    };
    let err = validate_htlc_spend(
        &entry,
        &path,
        &bad_sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        10,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrTimelockNotMet);

    let path = htlc_refund_selector(refund_key_id);
    let sig = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: mldsa_pubkey(1),
        signature: vec![0],
    };
    let err = validate_htlc_spend(
        &entry,
        &path,
        &sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        100,
    )
    .unwrap_err();
    assert!(matches!(
        err.code,
        ErrorCode::TxErrSigNoncanonical
            | ErrorCode::TxErrSigInvalid
            | ErrorCode::TxErrSighashTypeInvalid
    ));

    let wrong_path = htlc_refund_selector([0x77; 32]);
    let err = validate_htlc_spend(
        &entry,
        &wrong_path,
        &bad_sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        100,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);

    let malformed_refund = WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: refund_key_id.to_vec(),
        signature: vec![0x01, 0x00],
    };
    let err = validate_htlc_spend(
        &entry,
        &malformed_refund,
        &bad_sig,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        100,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let good_sig_shape = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: mldsa_pubkey(9),
        signature: mldsa_signature(8),
    };
    let err = validate_htlc_spend(
        &entry,
        &path,
        &good_sig_shape,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        100,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);

    let wrong_suite = WitnessItem {
        suite_id: 0xff,
        pubkey: vec![],
        signature: vec![],
    };
    let err = validate_htlc_spend(
        &entry,
        &path,
        &wrong_suite,
        &base_tx(),
        0,
        100,
        dummy_chain_id(),
        0,
        100,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn validate_p2pk_spend_rejects_canonicality_and_binding_errors() {
    let tx = base_tx();
    let pubkey = mldsa_pubkey(1);
    let entry = p2pk_entry_for_pubkey(&pubkey);
    let w = WitnessItem {
        suite_id: 0xff,
        pubkey: vec![],
        signature: vec![],
    };
    let err = validate_p2pk_spend(&entry, &w, &tx, 0, 100, dummy_chain_id(), 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);

    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![1],
        signature: vec![1],
    };
    let err = validate_p2pk_spend(&entry, &w, &tx, 0, 100, dummy_chain_id(), 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);

    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: mldsa_pubkey(2),
        signature: mldsa_signature(3),
    };
    let err = validate_p2pk_spend(&entry, &w, &tx, 0, 100, dummy_chain_id(), 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn validate_threshold_sig_spend_rejects_assignment_and_threshold_errors() {
    let tx = base_tx();
    let keys = vec![[1u8; 32], [2u8; 32]];
    let ws = vec![WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![],
        signature: vec![],
    }];
    let err = validate_threshold_sig_spend(&keys, 1, &ws, &tx, 0, 100, dummy_chain_id(), 0, "ctx")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let ws = vec![
        WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![1],
            signature: vec![],
        },
        WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        },
    ];
    let err = validate_threshold_sig_spend(&keys, 1, &ws, &tx, 0, 100, dummy_chain_id(), 0, "ctx")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let ws = vec![
        WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        },
        WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        },
    ];
    let err = validate_threshold_sig_spend(&keys, 1, &ws, &tx, 0, 100, dummy_chain_id(), 0, "ctx")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);

    let ws = vec![
        WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: vec![1],
            signature: vec![1],
        },
        WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        },
    ];
    let err = validate_threshold_sig_spend(&keys, 1, &ws, &tx, 0, 100, dummy_chain_id(), 0, "ctx")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);

    let ws = vec![
        WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: mldsa_pubkey(1),
            signature: mldsa_signature(2),
        },
        WitnessItem {
            suite_id: SUITE_ID_SENTINEL,
            pubkey: vec![],
            signature: vec![],
        },
    ];
    let err = validate_threshold_sig_spend(&keys, 1, &ws, &tx, 0, 100, dummy_chain_id(), 0, "ctx")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn validate_stealth_spend_rejects_noncanonical_and_bad_sighash() {
    let tx = base_tx();
    let entry = stealth_entry_for_pubkey(&mldsa_pubkey(1));
    assert!(parse_stealth_covenant_data(&entry.covenant_data).is_ok());
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: vec![1],
        signature: vec![1],
    };
    let err = validate_stealth_spend(&entry, &w, &tx, 0, 100, dummy_chain_id(), 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);

    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: mldsa_pubkey(1),
        signature: {
            let mut sig = vec![0x00; ML_DSA_87_SIG_BYTES as usize];
            sig.push(0x7f);
            sig
        },
    };
    let err = validate_stealth_spend(&entry, &w, &tx, 0, 100, dummy_chain_id(), 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSighashTypeInvalid);
}

#[test]
fn validate_stealth_spend_reaches_digest_and_verify_path() {
    let tx = base_tx();
    let pubkey = mldsa_pubkey(1);
    let entry = stealth_entry_for_pubkey(&pubkey);
    let mut sig = vec![0x00; ML_DSA_87_SIG_BYTES as usize];
    sig.push(SIGHASH_ALL);
    let w = WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey,
        signature: sig,
    };
    let err = validate_stealth_spend(&entry, &w, &tx, 0, 100, dummy_chain_id(), 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}
