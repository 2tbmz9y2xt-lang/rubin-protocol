use crate::constants::{
    COV_TYPE_CORE_STEALTH, COV_TYPE_HTLC, COV_TYPE_P2PK, LOCK_MODE_HEIGHT, MAX_HTLC_COVENANT_DATA,
    MAX_STEALTH_COVENANT_DATA, ML_KEM_1024_CT_BYTES, SIGHASH_ALL, SUITE_ID_ML_DSA_87,
    SUITE_ID_SENTINEL,
};
use crate::hash::sha3_256;
use crate::htlc::HtlcSpendContext;
use crate::suite_registry::SuiteRegistry;
use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
use crate::utxo_basic::UtxoEntry;
use crate::verify_sig_openssl::Mldsa87Keypair;
use crate::{sighash_v1_digest_with_cache, SighashV1PrehashCache};

pub(super) fn test_tx_context() -> (Tx, u32, u64, [u8; 32]) {
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

pub(super) fn htlc_spend_context(
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    block_height: u64,
    block_mtp: u64,
) -> HtlcSpendContext {
    HtlcSpendContext {
        input_index,
        input_value,
        chain_id,
        block_height,
        block_mtp,
    }
}

pub(super) fn sign_witness(
    keypair: &Mldsa87Keypair,
    tx: &Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
) -> WitnessItem {
    let mut cache = SighashV1PrehashCache::new(tx).expect("cache");
    let digest =
        sighash_v1_digest_with_cache(&mut cache, input_index, input_value, chain_id, SIGHASH_ALL)
            .expect("digest");
    let mut signature = keypair.sign_digest32(digest).expect("sign");
    signature.push(SIGHASH_ALL);
    WitnessItem {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey: keypair.pubkey_bytes(),
        signature,
    }
}

pub(super) fn encode_htlc_claim_payload(preimage: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + preimage.len());
    out.push(0x00);
    out.extend_from_slice(&(preimage.len() as u16).to_le_bytes());
    out.extend_from_slice(preimage);
    out
}

pub(super) fn make_stealth_entry(one_time_key_id: [u8; 32]) -> UtxoEntry {
    let mut out = vec![0u8; MAX_STEALTH_COVENANT_DATA as usize];
    out[ML_KEM_1024_CT_BYTES as usize..].copy_from_slice(&one_time_key_id);
    UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_CORE_STEALTH,
        covenant_data: out,
        creation_height: 0,
        created_by_coinbase: false,
    }
}

// Build a valid HTLC claim fixture shared by queued-spend tests.
pub(super) fn htlc_claim_fixture() -> (
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
