use super::*;
use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, TX_WIRE_VERSION};
use crate::tx::{parse_tx, Tx, TxInput, TxOutput};

struct StubSigner {
    pubkey: Vec<u8>,
    signature: Vec<u8>,
}

impl DigestSigner for StubSigner {
    fn pubkey_bytes(&self) -> Vec<u8> {
        self.pubkey.clone()
    }

    fn sign_digest32(&self, _digest32: [u8; 32]) -> Result<Vec<u8>, TxError> {
        Ok(self.signature.clone())
    }
}

struct ErrorSigner;

impl DigestSigner for ErrorSigner {
    fn pubkey_bytes(&self) -> Vec<u8> {
        test_pubkey(0x77)
    }

    fn sign_digest32(&self, _digest32: [u8; 32]) -> Result<Vec<u8>, TxError> {
        Err(TxError::new(
            ErrorCode::TxErrSigInvalid,
            "signer backend failure",
        ))
    }
}

fn test_pubkey(byte: u8) -> Vec<u8> {
    vec![byte; ML_DSA_87_PUBKEY_BYTES as usize]
}

fn test_signature(byte: u8) -> Vec<u8> {
    vec![byte; ML_DSA_87_SIG_BYTES as usize]
}

fn test_tx() -> Tx {
    Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x00,
        tx_nonce: 7,
        inputs: vec![TxInput {
            prev_txid: [0x11; 32],
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 9,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(&test_pubkey(0x22)),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    }
}

fn da_commit_tx() -> Tx {
    Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x01,
        tx_nonce: 7,
        inputs: Vec::new(),
        outputs: vec![TxOutput {
            value: 0,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: Vec::new(),
        }],
        locktime: 0,
        da_commit_core: Some(crate::tx::DaCommitCore {
            da_id: [0x10; 32],
            chunk_count: 1,
            retl_domain_id: [0x20; 32],
            batch_number: 9,
            tx_data_root: [0x30; 32],
            state_root: [0x40; 32],
            withdrawals_root: [0x50; 32],
            batch_sig_suite: 0x00,
            batch_sig: vec![0xaa, 0xbb],
        }),
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: vec![0xde, 0xad, 0xbe, 0xef],
    }
}

fn da_chunk_tx() -> Tx {
    Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x02,
        tx_nonce: 9,
        inputs: Vec::new(),
        outputs: vec![TxOutput {
            value: 0,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: Vec::new(),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: Some(crate::tx::DaChunkCore {
            da_id: [0x11; 32],
            chunk_index: 0,
            chunk_hash: [0x22; 32],
        }),
        witness: Vec::new(),
        da_payload: vec![0x01],
    }
}

fn test_utxos(pubkey: &[u8]) -> HashMap<Outpoint, UtxoEntry> {
    HashMap::from([(
        Outpoint {
            txid: [0x11; 32],
            vout: 0,
        },
        UtxoEntry {
            value: 10,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: p2pk_covenant_data_for_pubkey(pubkey),
            creation_height: 0,
            created_by_coinbase: false,
        },
    )])
}

mod marshal {
    use super::*;
    include!("marshal.rs.inc");
}

mod signing {
    use super::*;
    include!("signing.rs.inc");
}
