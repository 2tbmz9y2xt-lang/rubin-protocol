use super::*;
use crate::constants::{
    COV_TYPE_P2PK, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SIGHASH_ALL, SUITE_ID_ML_DSA_87,
    SUITE_ID_SENTINEL, VERIFY_COST_ML_DSA_87,
};
use crate::hash::sha3_256;
use crate::sighash_v1_digest_with_cache;
use crate::suite_registry::{NativeSuiteSet, RotationProvider, SuiteParams, SuiteRegistry};
use crate::tx::{Tx, TxInput, TxOutput, WitnessItem};
use crate::verify_sig_openssl::Mldsa87Keypair;
use crate::SighashV1PrehashCache;
use std::collections::BTreeMap;

struct TestSpendSetRotation {
    spend: NativeSuiteSet,
}

impl RotationProvider for TestSpendSetRotation {
    fn native_create_suites(&self, _height: u64) -> NativeSuiteSet {
        self.spend.clone()
    }

    fn native_spend_suites(&self, _height: u64) -> NativeSuiteSet {
        self.spend.clone()
    }
}

fn dummy_entry() -> UtxoEntry {
    UtxoEntry {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: vec![0u8; 100],
        creation_height: 0,
        created_by_coinbase: false,
    }
}

fn dummy_tx_ctx() -> (Tx, u32, u64, [u8; 32]) {
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
                value: 1,
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
        1,
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

fn make_p2pk_entry(pubkey: &[u8]) -> UtxoEntry {
    let pubkey_hash = sha3_256(pubkey);
    let mut covenant_data = vec![SUITE_ID_ML_DSA_87];
    covenant_data.extend_from_slice(&pubkey_hash);
    UtxoEntry {
        value: 100,
        covenant_type: COV_TYPE_P2PK,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    }
}

mod key_sig {
    use super::*;
    include!("key_sig.rs.inc");
}

mod p2pk {
    use super::*;
    include!("p2pk.rs.inc");
}

mod registry {
    use super::*;
    include!("registry.rs.inc");
}

mod threshold {
    use super::*;
    include!("threshold.rs.inc");
}
