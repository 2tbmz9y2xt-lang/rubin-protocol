use super::test_support::{
    encode_htlc_claim_payload, htlc_spend_context, make_stealth_entry, sign_witness,
    test_tx_context,
};
use super::*;
use crate::constants::{
    COV_TYPE_HTLC, COV_TYPE_P2PK, LOCK_MODE_HEIGHT, MAX_HTLC_COVENANT_DATA, SUITE_ID_SENTINEL,
};
use crate::hash::sha3_256;
use crate::htlc::{parse_htlc_covenant_data, validate_htlc_spend_q};
use crate::spend_verify::{validate_p2pk_spend_q, validate_threshold_sig_spend_q};
use crate::stealth::{parse_stealth_covenant_data, validate_stealth_spend_q};
use crate::suite_registry::SuiteRegistry;
use crate::tx::WitnessItem;
use crate::tx_helpers::p2pk_covenant_data_for_pubkey;
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::Mldsa87Keypair;
use crate::SighashV1PrehashCache;

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
        htlc_spend_context(input_index, input_value, chain_id, 1, 0),
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
