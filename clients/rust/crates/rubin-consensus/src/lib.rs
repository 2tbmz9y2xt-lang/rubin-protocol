//! RUBIN consensus library (wire, hashing domains, validation).
//!
//! This crate MUST implement consensus exactly as defined in:
//! - spec/RUBIN_L1_CANONICAL_v1.1.md
//!
//! Non-consensus policy MUST NOT be implemented here.

mod chainstate_hash;
mod encode;
mod parse;
mod pow;
mod sighash;
mod util;
mod validate;
mod wire;

pub use chainstate_hash::utxo_set_hash;
pub use encode::{
    block_header_bytes, tx_bytes, tx_no_witness_bytes, tx_output_bytes, witness_bytes,
    witness_item_bytes,
};
pub use parse::{parse_block_bytes, parse_tx_bytes};
pub use pow::block_header_hash;
pub use sighash::sighash_v1_digest;
pub use validate::{
    apply_block, apply_tx, compute_key_id, tx_weight, txid, validate_input_authorization,
};

pub const CONSENSUS_REVISION: &str = "v1.1";

pub const CORE_P2PK: u16 = 0x0000;
pub const CORE_TIMELOCK_V1: u16 = 0x0001;
pub const CORE_ANCHOR: u16 = 0x0002;
pub const CORE_HTLC_V1: u16 = 0x0100;
pub const CORE_VAULT_V1: u16 = 0x0101;
pub const CORE_HTLC_V2: u16 = 0x0102;
pub const CORE_DA_COMMIT: u16 = 0x0103;
pub const CORE_RESERVED_FUTURE: u16 = 0x00ff;

pub const SUITE_ID_SENTINEL: u8 = 0x00;
pub const SUITE_ID_ML_DSA: u8 = 0x01;
pub const SUITE_ID_SLH_DSA: u8 = 0x02;

pub const ML_DSA_PUBKEY_BYTES: usize = 2_592;
pub const SLH_DSA_PUBKEY_BYTES: usize = 64;
pub const ML_DSA_SIG_BYTES: usize = 4_627;
pub const SLH_DSA_SIG_MAX_BYTES: usize = 49_856;
pub const MAX_TX_INPUTS: usize = 1_024;
pub const MAX_TX_OUTPUTS: usize = 1_024;
pub const MAX_WITNESS_ITEMS: usize = 1_024;
pub const MAX_WITNESS_BYTES_PER_TX: usize = 100_000;

// DA (on-chain data availability) consensus caps (v2 wire, planning profile).
pub const MAX_DA_MANIFEST_BYTES_PER_TX: usize = 65_536;
pub const MAX_DA_CHUNK_BYTES_PER_TX: usize = 524_288;
pub const MAX_DA_BYTES_PER_BLOCK: u64 = 32_000_000;
pub const MAX_DA_COMMITS_PER_BLOCK: u64 = 128;
pub const MAX_DA_CHUNK_COUNT: u64 = 4_096;

pub const TX_VERSION_V2: u32 = 2;
pub const TX_KIND_STANDARD: u8 = 0x00;
pub const TX_KIND_DA_COMMIT: u8 = 0x01;
pub const TX_KIND_DA_CHUNK: u8 = 0x02;

pub const TIMELOCK_MODE_HEIGHT: u8 = 0x00;
pub const TIMELOCK_MODE_TIMESTAMP: u8 = 0x01;

// Block-level consensus constants (v1.1).
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
pub const MAX_ANCHOR_BYTES_PER_BLOCK: u64 = 131_072;
pub const MAX_ANCHOR_PAYLOAD_SIZE: usize = 65_536;
pub const WINDOW_SIZE: u64 = 2_016;
pub const TARGET_BLOCK_INTERVAL: u64 = 600;
pub const MAX_FUTURE_DRIFT: u64 = 7_200;
pub const COINBASE_MATURITY: u64 = 100;

// Signature verification cost model (consensus weight accounting) — must match spec + Go client.
pub const VERIFY_COST_ML_DSA: u64 = 8;
pub const VERIFY_COST_SLH_DSA: u64 = 64;

// Tx-level replay / sequence constraints.
pub const TX_NONCE_ZERO: u64 = 0;
pub const TX_MAX_SEQUENCE: u32 = 0x7fffffff;
pub const TX_COINBASE_PREVOUT_VOUT: u32 = u32::MAX;

pub const BLOCK_ERR_PARSE: &str = "BLOCK_ERR_PARSE";
pub const BLOCK_ERR_LINKAGE_INVALID: &str = "BLOCK_ERR_LINKAGE_INVALID";
pub const BLOCK_ERR_POW_INVALID: &str = "BLOCK_ERR_POW_INVALID";
pub const BLOCK_ERR_TARGET_INVALID: &str = "BLOCK_ERR_TARGET_INVALID";
pub const BLOCK_ERR_MERKLE_INVALID: &str = "BLOCK_ERR_MERKLE_INVALID";
pub const BLOCK_ERR_WEIGHT_EXCEEDED: &str = "BLOCK_ERR_WEIGHT_EXCEEDED";
pub const BLOCK_ERR_COINBASE_INVALID: &str = "BLOCK_ERR_COINBASE_INVALID";
pub const BLOCK_ERR_SUBSIDY_EXCEEDED: &str = "BLOCK_ERR_SUBSIDY_EXCEEDED";
pub const BLOCK_ERR_TIMESTAMP_OLD: &str = "BLOCK_ERR_TIMESTAMP_OLD";
pub const BLOCK_ERR_TIMESTAMP_FUTURE: &str = "BLOCK_ERR_TIMESTAMP_FUTURE";
pub const BLOCK_ERR_ANCHOR_BYTES_EXCEEDED: &str = "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED";

pub const TX_ERR_NONCE_REPLAY: &str = "TX_ERR_NONCE_REPLAY";
pub const TX_ERR_TX_NONCE_INVALID: &str = "TX_ERR_TX_NONCE_INVALID";
pub const TX_ERR_SEQUENCE_INVALID: &str = "TX_ERR_SEQUENCE_INVALID";
pub const TX_ERR_COINBASE_IMMATURE: &str = "TX_ERR_COINBASE_IMMATURE";
pub const TX_ERR_WITNESS_OVERFLOW: &str = "TX_ERR_WITNESS_OVERFLOW";

// MAX_TARGET is the maximum allowed PoW target. This implementation treats it as all-ones.
pub const MAX_TARGET: [u8; 32] = [0xffu8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub target: [u8; 32],
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Tx>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockValidationContext {
    pub height: u64,
    pub ancestor_headers: Vec<BlockHeader>, // ordered from oldest to newest, parent is last
    pub local_time: u64,
    pub local_time_set: bool,
    pub suite_id_02_active: bool,
    pub htlc_v2_active: bool,
}

pub fn compact_size_encode(n: u64) -> Vec<u8> {
    if n < 253 {
        return vec![n as u8];
    }
    if n <= 0xffff {
        let mut out = vec![0xfd];
        out.extend_from_slice(&(n as u16).to_le_bytes());
        return out;
    }
    if n <= 0xffff_ffff {
        let mut out = vec![0xfe];
        out.extend_from_slice(&(n as u32).to_le_bytes());
        return out;
    }
    let mut out = vec![0xff];
    out.extend_from_slice(&n.to_le_bytes());
    out
}

pub fn compact_size_decode(bytes: &[u8]) -> Result<(u64, usize), String> {
    if bytes.is_empty() {
        return Err("compactsize: empty".into());
    }
    let tag = bytes[0];
    if tag < 0xfd {
        return Ok((tag as u64, 1));
    }
    if tag == 0xfd {
        if bytes.len() < 3 {
            return Err("compactsize: truncated u16".into());
        }
        let n = u16::from_le_bytes([bytes[1], bytes[2]]) as u64;
        if n < 253 {
            return Err("compactsize: non-minimal u16".into());
        }
        return Ok((n, 3));
    }
    if tag == 0xfe {
        if bytes.len() < 5 {
            return Err("compactsize: truncated u32".into());
        }
        let n = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
        if n < 0x1_0000 {
            return Err("compactsize: non-minimal u32".into());
        }
        return Ok((n, 5));
    }
    if bytes.len() < 9 {
        return Err("compactsize: truncated u64".into());
    }
    let n = u64::from_le_bytes([
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
    ]);
    if n < 0x1_0000_0000 {
        return Err("compactsize: non-minimal u64".into());
    }
    Ok((n, 9))
}

pub fn hex_decode_strict(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.split_whitespace().collect();
    hex::decode(cleaned).map_err(|e| format!("hex decode error: {e}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub tx_kind: u8,
    pub tx_nonce: u64,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
    pub da_commit: Option<DACommitFields>,
    pub da_chunk: Option<DAChunkFields>,
    pub da_payload: Vec<u8>,
    pub witness: WitnessSection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DACommitFields {
    pub da_id: [u8; 32],
    pub chunk_count: u16,
    pub retl_domain_id: [u8; 32],
    pub batch_number: u64,
    pub tx_data_root: [u8; 32],
    pub state_root: [u8; 32],
    pub withdrawals_root: [u8; 32],
    pub batch_sig_suite: u8,
    pub batch_sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DAChunkFields {
    pub da_id: [u8; 32],
    pub chunk_index: u16,
    pub chunk_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    pub value: u64,
    pub covenant_type: u16,
    pub covenant_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxOutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub output: TxOutput,
    pub creation_height: u64,
    pub created_by_coinbase: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSection {
    pub witnesses: Vec<WitnessItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessItem {
    pub suite_id: u8,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubin_crypto::CryptoProvider;
    use std::collections::HashMap;

    struct TestProvider;

    impl TestProvider {
        fn simple_hash(input: &[u8]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, byte) in input.iter().enumerate() {
                out[i % 32] = out[i % 32].wrapping_add(*byte).wrapping_add(i as u8);
            }
            out
        }
    }

    impl rubin_crypto::CryptoProvider for TestProvider {
        fn sha3_256(&self, input: &[u8]) -> Result<[u8; 32], String> {
            Ok(Self::simple_hash(input))
        }

        fn verify_mldsa87(
            &self,
            _pubkey: &[u8],
            _sig: &[u8],
            _digest32: &[u8; 32],
        ) -> Result<bool, String> {
            Ok(true)
        }

        fn verify_slhdsa_shake_256f(
            &self,
            _pubkey: &[u8],
            _sig: &[u8],
            _digest32: &[u8; 32],
        ) -> Result<bool, String> {
            Ok(true)
        }
    }

    fn make_htlc_output(
        preimage: &[u8; 32],
        lock_height: u64,
        claim_key_id: [u8; 32],
        refund_key_id: [u8; 32],
    ) -> TxOutput {
        let mut covenant_data = Vec::with_capacity(105);
        covenant_data.extend_from_slice(&TestProvider::simple_hash(preimage));
        covenant_data.push(TIMELOCK_MODE_HEIGHT);
        covenant_data.extend_from_slice(&lock_height.to_le_bytes());
        covenant_data.extend_from_slice(&claim_key_id);
        covenant_data.extend_from_slice(&refund_key_id);
        TxOutput {
            value: 100,
            covenant_type: CORE_HTLC_V1,
            covenant_data,
        }
    }

    fn make_vault_output(
        owner_key_id: [u8; 32],
        lock_height: u64,
        recovery_key_id: [u8; 32],
    ) -> TxOutput {
        let mut covenant_data = Vec::with_capacity(73);
        covenant_data.extend_from_slice(&owner_key_id);
        covenant_data.push(TIMELOCK_MODE_HEIGHT);
        covenant_data.extend_from_slice(&lock_height.to_le_bytes());
        covenant_data.extend_from_slice(&recovery_key_id);
        TxOutput {
            value: 100,
            covenant_type: CORE_VAULT_V1,
            covenant_data,
        }
    }

    fn make_input(script_sig: Vec<u8>, sequence: u32) -> TxInput {
        TxInput {
            prev_txid: [0u8; 32],
            prev_vout: 0,
            script_sig,
            sequence,
        }
    }

    fn make_input_witness(suite_id: u8, pubkey: Vec<u8>, sig: Vec<u8>) -> WitnessItem {
        WitnessItem {
            suite_id,
            pubkey,
            signature: sig,
        }
    }

    fn make_tx(input: TxInput, witness: WitnessItem) -> Tx {
        Tx {
            version: TX_VERSION_V2,
            tx_kind: TX_KIND_STANDARD,
            tx_nonce: 1,
            inputs: vec![input],
            outputs: vec![],
            locktime: 0,
            da_commit: None,
            da_chunk: None,
            da_payload: Vec::new(),
            witness: WitnessSection {
                witnesses: vec![witness],
            },
        }
    }

    #[test]
    fn compact_size_roundtrip_boundaries() {
        let cases = [
            0u64,
            1,
            252,
            253,
            65535,
            65536,
            305_419_896,
            4_294_967_296,
            u64::MAX,
        ];
        for n in cases {
            let enc = compact_size_encode(n);
            let (dec, used) = compact_size_decode(&enc).expect("decode");
            assert_eq!(dec, n);
            assert_eq!(used, enc.len());
        }
    }

    #[test]
    fn compact_size_rejects_non_minimal() {
        let (n, used) = compact_size_decode(&[0xfc]).expect("decode");
        assert_eq!(n, 252);
        assert_eq!(used, 1);

        assert!(compact_size_decode(&[0xfd, 0x01, 0x00]).is_err());
        assert!(compact_size_decode(&[0xfe, 0xff, 0x00, 0x00, 0x00]).is_err());
        assert!(
            compact_size_decode(&[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err()
        );
    }

    #[test]
    fn validate_htlc_rejects_bad_script_sig_len() {
        let p = TestProvider;
        let preimage = [0x11u8; 32];
        let claim_key = TestProvider::simple_hash(b"claim-key");
        let refund_key = TestProvider::simple_hash(b"refund-key");
        let prevout = make_htlc_output(&preimage, 20, claim_key, refund_key);

        let tx = make_tx(
            make_input(vec![1u8; 16], 1),
            make_input_witness(
                SUITE_ID_ML_DSA,
                vec![7u8; ML_DSA_PUBKEY_BYTES],
                vec![7u8; ML_DSA_SIG_BYTES],
            ),
        );

        let chain_id = [0u8; 32];
        let err = validate_input_authorization(
            &p, &chain_id, &tx, 0, 100, &prevout, 0, 0, 0, true, false,
        )
        .unwrap_err();
        assert_eq!(err, "TX_ERR_PARSE");
    }

    #[test]
    fn validate_htlc_refund_requires_lock() {
        let p = TestProvider;
        let preimage = [0x33u8; 32];
        let pubkey = vec![0x22u8; ML_DSA_PUBKEY_BYTES];
        let refund_pubkey_id = p.sha3_256(&pubkey).expect("hash");
        let claim_key = [0u8; 32];
        let prevout = make_htlc_output(&preimage, 100, claim_key, refund_pubkey_id);

        let tx = make_tx(
            make_input(vec![], 1),
            make_input_witness(SUITE_ID_ML_DSA, pubkey, vec![9u8; ML_DSA_SIG_BYTES]),
        );

        let chain_id = [0u8; 32];
        let err = validate_input_authorization(
            &p, &chain_id, &tx, 0, 100, &prevout, 0, 10, 0, true, false,
        )
        .unwrap_err();
        assert_eq!(err, "TX_ERR_TIMELOCK_NOT_MET");
    }

    #[test]
    fn validate_vault_owner_bypasses_lock() {
        let p = TestProvider;
        let owner_pubkey = vec![0x44u8; ML_DSA_PUBKEY_BYTES];
        let recovery_pubkey = vec![0x55u8; ML_DSA_PUBKEY_BYTES];
        let owner_key_id = p.sha3_256(&owner_pubkey).expect("hash");
        let recovery_key_id = p.sha3_256(&recovery_pubkey).expect("hash");
        let prevout = make_vault_output(owner_key_id, 1000, recovery_key_id);

        let tx = make_tx(
            make_input(vec![], 1),
            make_input_witness(SUITE_ID_ML_DSA, owner_pubkey, vec![1u8; ML_DSA_SIG_BYTES]),
        );

        let chain_id = [0u8; 32];
        let ok = validate_input_authorization(
            &p, &chain_id, &tx, 0, 100, &prevout, 0, 10, 0, true, false,
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn validate_vault_recovery_respects_lock() {
        let p = TestProvider;
        let owner_pubkey = vec![0x44u8; ML_DSA_PUBKEY_BYTES];
        let recovery_pubkey = vec![0x55u8; ML_DSA_PUBKEY_BYTES];
        let owner_key_id = p.sha3_256(&owner_pubkey).expect("hash");
        let recovery_key_id = p.sha3_256(&recovery_pubkey).expect("hash");
        let prevout = make_vault_output(owner_key_id, 1000, recovery_key_id);

        let tx = make_tx(
            make_input(vec![], 1),
            make_input_witness(
                SUITE_ID_ML_DSA,
                recovery_pubkey,
                vec![2u8; ML_DSA_SIG_BYTES],
            ),
        );

        let chain_id = [0u8; 32];
        let err = validate_input_authorization(
            &p, &chain_id, &tx, 0, 100, &prevout, 0, 10, 0, true, false,
        )
        .unwrap_err();
        assert_eq!(err, "TX_ERR_TIMELOCK_NOT_MET");
    }

    fn make_apply_tx_prevout(value: u64, covenant_type: u16, covenant_data: Vec<u8>) -> TxOutput {
        TxOutput {
            value,
            covenant_type,
            covenant_data,
        }
    }

    fn make_apply_tx_input(txid: [u8; 32], vout: u32) -> TxInput {
        TxInput {
            prev_txid: txid,
            prev_vout: vout,
            script_sig: Vec::new(),
            sequence: 0,
        }
    }

    fn make_apply_tx_tx(
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        witness: Vec<WitnessItem>,
    ) -> Tx {
        Tx {
            version: TX_VERSION_V2,
            tx_kind: TX_KIND_STANDARD,
            tx_nonce: 1,
            inputs,
            outputs,
            locktime: 0,
            da_commit: None,
            da_chunk: None,
            da_payload: Vec::new(),
            witness: WitnessSection { witnesses: witness },
        }
    }

    #[test]
    fn apply_tx_rejects_missing_utxo() {
        let p = TestProvider;
        let dummy_key_id = p.sha3_256(&vec![0x11u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let valid_p2pk_data = [vec![SUITE_ID_ML_DSA], dummy_key_id.to_vec()].concat();
        let tx = make_apply_tx_tx(
            vec![make_apply_tx_input([1u8; 32], 0)],
            vec![TxOutput {
                value: 10,
                covenant_type: CORE_P2PK,
                covenant_data: valid_p2pk_data,
            }],
            vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: vec![0x11u8; ML_DSA_PUBKEY_BYTES],
                signature: vec![0x22u8; ML_DSA_SIG_BYTES],
            }],
        );

        let err = apply_tx(
            &p,
            &[0u8; 32],
            &tx,
            &HashMap::<TxOutPoint, UtxoEntry>::new(),
            0,
            0,
            true,
            false,
        )
        .unwrap_err();
        assert_eq!(err, "TX_ERR_MISSING_UTXO");
    }

    #[test]
    fn apply_tx_rejects_duplicate_prevout() {
        let p = TestProvider;
        let txid = [2u8; 32];
        let key_id = p.sha3_256(&[0x11u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let prevout = make_apply_tx_prevout(
            200,
            CORE_P2PK,
            [vec![SUITE_ID_ML_DSA], key_id.to_vec()].concat(),
        );
        let witness = vec![
            WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: vec![0x11u8; ML_DSA_PUBKEY_BYTES],
                signature: vec![0x22u8; ML_DSA_SIG_BYTES],
            },
            WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: vec![0x11u8; ML_DSA_PUBKEY_BYTES],
                signature: vec![0x22u8; ML_DSA_SIG_BYTES],
            },
        ];
        let tx = make_apply_tx_tx(
            vec![make_apply_tx_input(txid, 0), make_apply_tx_input(txid, 0)],
            vec![TxOutput {
                value: 100,
                covenant_type: CORE_P2PK,
                covenant_data: Vec::new(),
            }],
            witness,
        );

        let mut utxo = HashMap::new();
        utxo.insert(
            TxOutPoint { txid, vout: 0 },
            UtxoEntry {
                output: prevout,
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let err = apply_tx(&p, &[0u8; 32], &tx, &utxo, 0, 0, true, false).unwrap_err();
        assert_eq!(err, "TX_ERR_PARSE");
    }

    #[test]
    fn apply_tx_rejects_value_conservation_violation() {
        let p = TestProvider;
        let txid = [3u8; 32];
        let key_id = p.sha3_256(&[0x33u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let prevout = make_apply_tx_prevout(
            100,
            CORE_P2PK,
            [vec![SUITE_ID_ML_DSA], key_id.to_vec()].concat(),
        );
        let out_key_id = p.sha3_256(&[0x33u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let valid_out_data = [vec![SUITE_ID_ML_DSA], out_key_id.to_vec()].concat();
        let tx = make_apply_tx_tx(
            vec![make_apply_tx_input(txid, 0)],
            vec![TxOutput {
                value: 101,
                covenant_type: CORE_P2PK,
                covenant_data: valid_out_data,
            }],
            vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: vec![0x33u8; ML_DSA_PUBKEY_BYTES],
                signature: vec![0x44u8; ML_DSA_SIG_BYTES],
            }],
        );

        let mut utxo = HashMap::new();
        utxo.insert(
            TxOutPoint { txid, vout: 0 },
            UtxoEntry {
                output: prevout,
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        let err = apply_tx(&p, &[0u8; 32], &tx, &utxo, 0, 0, true, false).unwrap_err();
        assert_eq!(err, "TX_ERR_VALUE_CONSERVATION");
    }

    #[test]
    fn apply_tx_accepts_valid_p2pk_spend() {
        let p = TestProvider;
        let txid = [4u8; 32];
        let pubkey = vec![0x55u8; ML_DSA_PUBKEY_BYTES];
        let key_id = p.sha3_256(&pubkey).unwrap();
        let prevout = TxOutput {
            value: 100,
            covenant_type: CORE_P2PK,
            covenant_data: [vec![SUITE_ID_ML_DSA], key_id.to_vec()].concat(),
        };
        let out_key_id = p.sha3_256(&vec![0x55u8; ML_DSA_PUBKEY_BYTES]).unwrap();
        let valid_out_data = [vec![SUITE_ID_ML_DSA], out_key_id.to_vec()].concat();
        let tx = make_apply_tx_tx(
            vec![make_apply_tx_input(txid, 0)],
            vec![TxOutput {
                value: 90,
                covenant_type: CORE_P2PK,
                covenant_data: valid_out_data,
            }],
            vec![WitnessItem {
                suite_id: SUITE_ID_ML_DSA,
                pubkey: pubkey.clone(),
                signature: vec![0x66u8; ML_DSA_SIG_BYTES],
            }],
        );

        let mut utxo = HashMap::new();
        utxo.insert(
            TxOutPoint { txid, vout: 0 },
            UtxoEntry {
                output: prevout,
                creation_height: 0,
                created_by_coinbase: false,
            },
        );

        apply_tx(&p, &[0u8; 32], &tx, &utxo, 0, 0, true, false).unwrap();
    }
}
