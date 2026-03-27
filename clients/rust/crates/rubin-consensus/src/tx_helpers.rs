use std::collections::HashMap;

use crate::compactsize::encode_compact_size;
use crate::constants::{
    COV_TYPE_P2PK, MAX_P2PK_COVENANT_DATA, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
    SIGHASH_ALL, SUITE_ID_ML_DSA_87,
};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::sighash::{sighash_v1_digest_with_cache, SighashV1PrehashCache};
use crate::tx::{da_core_fields_bytes, Tx, WitnessItem};
use crate::utxo_basic::{Outpoint, UtxoEntry};

pub trait DigestSigner {
    fn pubkey_bytes(&self) -> Vec<u8>;
    fn sign_digest32(&self, digest32: [u8; 32]) -> Result<Vec<u8>, TxError>;
}

pub fn p2pk_covenant_data_for_pubkey(pubkey: &[u8]) -> Vec<u8> {
    let key_id = sha3_256(pubkey);
    let mut out = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    out[0] = SUITE_ID_ML_DSA_87;
    out[1..33].copy_from_slice(&key_id);
    out
}

pub fn marshal_tx(tx: &Tx) -> Result<Vec<u8>, TxError> {
    let mut out = Vec::new();

    out.extend_from_slice(&tx.version.to_le_bytes());
    out.push(tx.tx_kind);
    out.extend_from_slice(&tx.tx_nonce.to_le_bytes());

    encode_compact_size(tx.inputs.len() as u64, &mut out);
    for input in &tx.inputs {
        out.extend_from_slice(&input.prev_txid);
        out.extend_from_slice(&input.prev_vout.to_le_bytes());
        encode_compact_size(input.script_sig.len() as u64, &mut out);
        out.extend_from_slice(&input.script_sig);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }

    encode_compact_size(tx.outputs.len() as u64, &mut out);
    for output in &tx.outputs {
        out.extend_from_slice(&output.value.to_le_bytes());
        out.extend_from_slice(&output.covenant_type.to_le_bytes());
        encode_compact_size(output.covenant_data.len() as u64, &mut out);
        out.extend_from_slice(&output.covenant_data);
    }

    out.extend_from_slice(&tx.locktime.to_le_bytes());
    out.extend_from_slice(&da_core_fields_bytes(tx)?);

    encode_compact_size(tx.witness.len() as u64, &mut out);
    for item in &tx.witness {
        out.push(item.suite_id);
        encode_compact_size(item.pubkey.len() as u64, &mut out);
        out.extend_from_slice(&item.pubkey);
        encode_compact_size(item.signature.len() as u64, &mut out);
        out.extend_from_slice(&item.signature);
    }

    encode_compact_size(tx.da_payload.len() as u64, &mut out);
    out.extend_from_slice(&tx.da_payload);

    Ok(out)
}

pub fn sign_transaction(
    tx: &mut Tx,
    utxo_set: &HashMap<Outpoint, UtxoEntry>,
    chain_id: [u8; 32],
    signer: &impl DigestSigner,
) -> Result<(), TxError> {
    if tx.inputs.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-coinbase must have at least one input",
        ));
    }

    let pubkey = signer.pubkey_bytes();
    if pubkey.len() as u64 != ML_DSA_87_PUBKEY_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrSigNoncanonical,
            "non-canonical ML-DSA public key length",
        ));
    }
    let key_id = sha3_256(&pubkey);

    let mut sighash_cache = SighashV1PrehashCache::new(tx)?;
    let mut witness = Vec::with_capacity(tx.inputs.len());
    for (idx, input) in tx.inputs.iter().enumerate() {
        let outpoint = Outpoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        let entry = utxo_set.get(&outpoint).ok_or_else(|| {
            TxError::new(ErrorCode::TxErrMissingUtxo, "utxo not found for signing")
        })?;
        if entry.covenant_type != COV_TYPE_P2PK {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "unsupported covenant type for signing",
            ));
        }
        if entry.covenant_data.len() as u64 != MAX_P2PK_COVENANT_DATA
            || entry.covenant_data[0] != SUITE_ID_ML_DSA_87
        {
            return Err(TxError::new(
                ErrorCode::TxErrCovenantTypeInvalid,
                "CORE_P2PK covenant_data invalid",
            ));
        }
        if entry.covenant_data[1..33] != key_id {
            return Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "signer key binding mismatch",
            ));
        }

        let digest = sighash_v1_digest_with_cache(
            &mut sighash_cache,
            idx as u32,
            entry.value,
            chain_id,
            SIGHASH_ALL,
        )?;
        let mut signature = signer.sign_digest32(digest)?;
        if signature.len() as u64 != ML_DSA_87_SIG_BYTES {
            return Err(TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "non-canonical ML-DSA signature length",
            ));
        }
        signature.push(SIGHASH_ALL);
        witness.push(WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: pubkey.clone(),
            signature,
        });
    }

    tx.witness = witness;
    Ok(())
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn marshal_tx_roundtrips_via_parse_tx() {
        let tx = test_tx();
        let bytes = marshal_tx(&tx).expect("marshal");
        let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse");
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, tx);
    }

    #[test]
    fn sign_transaction_populates_canonical_mldsa_witness() {
        let pubkey = test_pubkey(0x33);
        let signer = StubSigner {
            pubkey: pubkey.clone(),
            signature: test_signature(0x44),
        };
        let mut tx = test_tx();
        let chain_id = [0x55; 32];

        sign_transaction(&mut tx, &test_utxos(&pubkey), chain_id, &signer).expect("sign");

        assert_eq!(tx.witness.len(), 1);
        let item = &tx.witness[0];
        assert_eq!(item.suite_id, SUITE_ID_ML_DSA_87);
        assert_eq!(item.pubkey, pubkey);
        assert_eq!(item.signature.len(), (ML_DSA_87_SIG_BYTES + 1) as usize);
        assert_eq!(item.signature.last(), Some(&SIGHASH_ALL));

        let bytes = marshal_tx(&tx).expect("marshal signed tx");
        let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse signed tx");
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, tx);
    }

    #[test]
    fn sign_transaction_rejects_utxo_key_binding_mismatch() {
        let signer = StubSigner {
            pubkey: test_pubkey(0x33),
            signature: test_signature(0x44),
        };
        let mut tx = test_tx();
        let err = sign_transaction(&mut tx, &test_utxos(&test_pubkey(0x22)), [0u8; 32], &signer)
            .expect_err("key mismatch must fail");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }

    #[test]
    fn sign_transaction_rejects_noncanonical_signer_lengths() {
        let signer = StubSigner {
            pubkey: vec![0u8; (ML_DSA_87_PUBKEY_BYTES as usize) - 1],
            signature: test_signature(0x44),
        };
        let mut tx = test_tx();
        let err = sign_transaction(&mut tx, &test_utxos(&test_pubkey(0x33)), [0u8; 32], &signer)
            .expect_err("bad pubkey len must fail");
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn sign_transaction_rejects_empty_input_list() {
        let signer = StubSigner {
            pubkey: test_pubkey(0x33),
            signature: test_signature(0x44),
        };
        let mut tx = test_tx();
        tx.inputs.clear();
        let err =
            sign_transaction(&mut tx, &HashMap::new(), [0u8; 32], &signer).expect_err("empty");
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn sign_transaction_rejects_missing_utxo() {
        let signer = StubSigner {
            pubkey: test_pubkey(0x33),
            signature: test_signature(0x44),
        };
        let mut tx = test_tx();
        let err =
            sign_transaction(&mut tx, &HashMap::new(), [0u8; 32], &signer).expect_err("missing");
        assert_eq!(err.code, ErrorCode::TxErrMissingUtxo);
    }

    #[test]
    fn sign_transaction_rejects_non_p2pk_signing_entry() {
        let signer = StubSigner {
            pubkey: test_pubkey(0x33),
            signature: test_signature(0x44),
        };
        let mut tx = test_tx();
        let utxos = HashMap::from([(
            Outpoint {
                txid: [0x11; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 10,
                covenant_type: 0x0104,
                covenant_data: vec![1, 1],
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]);
        let err =
            sign_transaction(&mut tx, &utxos, [0u8; 32], &signer).expect_err("non-p2pk must fail");
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn sign_transaction_rejects_invalid_p2pk_covenant_data() {
        let signer = StubSigner {
            pubkey: test_pubkey(0x33),
            signature: test_signature(0x44),
        };
        let mut tx = test_tx();
        let utxos = HashMap::from([(
            Outpoint {
                txid: [0x11; 32],
                vout: 0,
            },
            UtxoEntry {
                value: 10,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: vec![SUITE_ID_ML_DSA_87; 32],
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]);
        let err = sign_transaction(&mut tx, &utxos, [0u8; 32], &signer)
            .expect_err("invalid covenant data");
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn sign_transaction_rejects_noncanonical_signature_length() {
        let pubkey = test_pubkey(0x33);
        let signer = StubSigner {
            pubkey: pubkey.clone(),
            signature: vec![0x44; (ML_DSA_87_SIG_BYTES as usize) - 1],
        };
        let mut tx = test_tx();
        let err =
            sign_transaction(&mut tx, &test_utxos(&pubkey), [0u8; 32], &signer).expect_err("sig");
        assert_eq!(err.code, ErrorCode::TxErrSigNoncanonical);
    }

    #[test]
    fn sign_transaction_propagates_signer_errors() {
        let pubkey = test_pubkey(0x77);
        let mut tx = test_tx();
        let err = sign_transaction(&mut tx, &test_utxos(&pubkey), [0u8; 32], &ErrorSigner)
            .expect_err("signer error");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    }
}

#[cfg(kani)]
mod verification {
    use super::*;
    use crate::constants::{COV_TYPE_P2PK, TX_WIRE_VERSION};
    use crate::tx::{parse_tx, Tx, TxInput, TxOutput};

    // This proof intentionally keeps the transaction shape bounded:
    // one input, one output, tx_kind=0x00, empty script/covenant/witness data.
    // That is enough to exercise the live marshal/parse wire helpers without
    // pretending Kani can search the full unbounded transaction space or
    // paying solver cost for allocator-heavy optional vectors.
    #[kani::proof]
    #[kani::unwind(16)]
    fn verify_marshal_tx_roundtrip_bounded_shape() {
        let tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 7,
            inputs: vec![TxInput {
                prev_txid: [0x11; 32],
                prev_vout: 3,
                script_sig: Vec::new(),
                sequence: 9,
            }],
            outputs: vec![TxOutput {
                value: 11,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: Vec::new(),
            }],
            locktime: 5,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };

        let bytes = marshal_tx(&tx).expect("marshal bounded tx");
        let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse bounded tx");
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.version, tx.version);
        assert_eq!(parsed.tx_kind, tx.tx_kind);
        assert_eq!(parsed.tx_nonce, tx.tx_nonce);
        assert_eq!(parsed.locktime, tx.locktime);
        assert_eq!(parsed.da_commit_core, tx.da_commit_core);
        assert_eq!(parsed.da_chunk_core, tx.da_chunk_core);
        assert!(parsed.da_payload.is_empty());
        assert!(parsed.witness.is_empty());
        assert_eq!(parsed.inputs.len(), 1);
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.inputs[0].prev_vout, tx.inputs[0].prev_vout);
        assert_eq!(parsed.inputs[0].sequence, tx.inputs[0].sequence);
        assert!(parsed.inputs[0].script_sig.is_empty());
        assert_eq!(parsed.outputs[0].value, tx.outputs[0].value);
        assert_eq!(parsed.outputs[0].covenant_type, tx.outputs[0].covenant_type);
        assert!(parsed.outputs[0].covenant_data.is_empty());
        assert_eq!(marshal_tx(&parsed).expect("re-marshal"), bytes);
    }
}
