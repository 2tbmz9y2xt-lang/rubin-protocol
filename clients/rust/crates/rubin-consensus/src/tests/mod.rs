use crate::constants::*;
use crate::error::ErrorCode;
use crate::hash::sha3_256;
use crate::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
use crate::pow::{pow_check, retarget_v1, retarget_v1_clamped};
use crate::sighash_v1_digest;
use crate::{
    apply_non_coinbase_tx_basic, apply_non_coinbase_tx_basic_with_mtp, block_hash,
    merkle_root_txids, parse_block_bytes, parse_tx, validate_block_basic,
    validate_block_basic_at_height, validate_block_basic_with_context_and_fees_at_height,
    validate_tx_covenants_genesis, Outpoint, UtxoEntry, BLOCK_HEADER_BYTES,
};
use num_bigint::BigUint;
use num_traits::One;
use std::collections::HashMap;

const ZERO_CHAIN_ID: [u8; 32] = [0u8; 32];

fn minimal_tx_bytes() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes());
    b.push(0x00); // input_count
    b.push(0x00); // output_count
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    b.push(0x00); // witness_count
    b.push(0x00); // da_payload_len
    b
}

fn core_end() -> usize {
    // version(4) + tx_kind(1) + tx_nonce(8) + input_count(1) + output_count(1) + locktime(4)
    4 + 1 + 8 + 1 + 1 + 4
}

fn build_block_bytes(
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    target: [u8; 32],
    nonce: u64,
    txs: &[Vec<u8>],
) -> Vec<u8> {
    assert!(!txs.is_empty());
    let mut header = Vec::with_capacity(BLOCK_HEADER_BYTES);
    header.extend_from_slice(&1u32.to_le_bytes()); // version
    header.extend_from_slice(&prev_hash);
    header.extend_from_slice(&merkle_root);
    header.extend_from_slice(&1u64.to_le_bytes()); // timestamp
    header.extend_from_slice(&target);
    header.extend_from_slice(&nonce.to_le_bytes());
    assert_eq!(header.len(), BLOCK_HEADER_BYTES);

    let mut b = header;
    crate::compactsize::encode_compact_size(txs.len() as u64, &mut b);
    for tx in txs {
        b.extend_from_slice(tx);
    }
    b
}

fn tx_with_one_output(value: u64, covenant_type: u16, covenant_data: &[u8]) -> Vec<u8> {
    tx_with_outputs(&[TestOutput {
        value,
        covenant_type,
        covenant_data: covenant_data.to_vec(),
    }])
}

#[derive(Clone)]
struct TestOutput {
    value: u64,
    covenant_type: u16,
    covenant_data: Vec<u8>,
}

fn tx_with_outputs(outputs: &[TestOutput]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(0, &mut b); // input_count
    crate::compactsize::encode_compact_size(outputs.len() as u64, &mut b); // output_count
    for out in outputs {
        b.extend_from_slice(&out.value.to_le_bytes());
        b.extend_from_slice(&out.covenant_type.to_le_bytes());
        crate::compactsize::encode_compact_size(out.covenant_data.len() as u64, &mut b);
        b.extend_from_slice(&out.covenant_data);
    }
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

fn tx_with_nonce_and_outputs(nonce: u64, outputs: &[TestOutput]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x00); // tx_kind
    b.extend_from_slice(&nonce.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    b.extend_from_slice(&[0u8; 32]); // prev_txid
    b.extend_from_slice(&0u32.to_le_bytes()); // prev_vout
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(outputs.len() as u64, &mut b); // output_count
    for out in outputs {
        b.extend_from_slice(&out.value.to_le_bytes());
        b.extend_from_slice(&out.covenant_type.to_le_bytes());
        crate::compactsize::encode_compact_size(out.covenant_data.len() as u64, &mut b);
        b.extend_from_slice(&out.covenant_data);
    }
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

fn da_commit_tx(
    da_id: [u8; 32],
    chunk_count: u16,
    payload_commitment: [u8; 32],
    tx_nonce: u64,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x01); // tx_kind
    b.extend_from_slice(&tx_nonce.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    let mut prev_txid = [0u8; 32];
    prev_txid[0] = tx_nonce as u8;
    b.extend_from_slice(&prev_txid);
    b.extend_from_slice(&0u32.to_le_bytes()); // prev_vout
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(1, &mut b); // output_count
    b.extend_from_slice(&0u64.to_le_bytes()); // value
    b.extend_from_slice(&COV_TYPE_DA_COMMIT.to_le_bytes());
    crate::compactsize::encode_compact_size(32, &mut b); // covenant_data_len
    b.extend_from_slice(&payload_commitment);
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    b.extend_from_slice(&da_id);
    b.extend_from_slice(&chunk_count.to_le_bytes());
    b.extend_from_slice(&[0x10u8; 32]); // retl_domain_id
    b.extend_from_slice(&1u64.to_le_bytes()); // batch_number
    b.extend_from_slice(&[0x11u8; 32]); // tx_data_root
    b.extend_from_slice(&[0x12u8; 32]); // state_root
    b.extend_from_slice(&[0x13u8; 32]); // withdrawals_root
    b.push(0x00); // batch_sig_suite
    crate::compactsize::encode_compact_size(0, &mut b); // batch_sig_len
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

fn da_chunk_tx(
    da_id: [u8; 32],
    chunk_index: u16,
    chunk_hash: [u8; 32],
    da_payload: &[u8],
    tx_nonce: u64,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x02); // tx_kind
    b.extend_from_slice(&tx_nonce.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    let mut prev_txid = [0u8; 32];
    prev_txid[0] = tx_nonce as u8;
    b.extend_from_slice(&prev_txid);
    b.extend_from_slice(&0u32.to_le_bytes()); // prev_vout
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(0, &mut b); // output_count
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    b.extend_from_slice(&da_id);
    b.extend_from_slice(&chunk_index.to_le_bytes());
    b.extend_from_slice(&chunk_hash);
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(da_payload.len() as u64, &mut b); // da_payload_len
    b.extend_from_slice(da_payload);
    b
}

fn da_chunk_tx_with_anchor_outputs(
    da_id: [u8; 32],
    chunk_index: u16,
    chunk_hash: [u8; 32],
    da_payload: &[u8],
    tx_nonce: u64,
    anchor_output_count: usize,
    anchor_payload_len: usize,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x02); // tx_kind
    b.extend_from_slice(&tx_nonce.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    let mut prev_txid = [0u8; 32];
    prev_txid[0] = tx_nonce as u8;
    b.extend_from_slice(&prev_txid);
    b.extend_from_slice(&0u32.to_le_bytes()); // prev_vout
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(anchor_output_count as u64, &mut b); // output_count
    for i in 0..anchor_output_count {
        b.extend_from_slice(&0u64.to_le_bytes()); // value
        b.extend_from_slice(&COV_TYPE_ANCHOR.to_le_bytes());
        crate::compactsize::encode_compact_size(anchor_payload_len as u64, &mut b);
        b.extend(vec![0x40 + (i as u8); anchor_payload_len]);
    }
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    b.extend_from_slice(&da_id);
    b.extend_from_slice(&chunk_index.to_le_bytes());
    b.extend_from_slice(&chunk_hash);
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(da_payload.len() as u64, &mut b); // da_payload_len
    b.extend_from_slice(da_payload);
    b
}

fn coinbase_tx_with_outputs(locktime: u32, outputs: &[TestOutput]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes()); // version
    b.push(0x00); // tx_kind
    b.extend_from_slice(&0u64.to_le_bytes()); // tx_nonce
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    b.extend_from_slice(&[0u8; 32]); // prev_txid
    b.extend_from_slice(&u32::MAX.to_le_bytes()); // prev_vout
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&u32::MAX.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(outputs.len() as u64, &mut b); // output_count
    for out in outputs {
        b.extend_from_slice(&out.value.to_le_bytes());
        b.extend_from_slice(&out.covenant_type.to_le_bytes());
        crate::compactsize::encode_compact_size(out.covenant_data.len() as u64, &mut b);
        b.extend_from_slice(&out.covenant_data);
    }
    b.extend_from_slice(&locktime.to_le_bytes());
    crate::compactsize::encode_compact_size(0, &mut b); // witness_count
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

fn coinbase_with_witness_commitment(locktime: u32, non_coinbase_txs: &[Vec<u8>]) -> Vec<u8> {
    let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(1 + non_coinbase_txs.len());
    wtxids.push([0u8; 32]);
    for txb in non_coinbase_txs {
        let (_tx, _txid, wtxid, _n) = parse_tx(txb).expect("parse non-coinbase");
        wtxids.push(wtxid);
    }

    let wroot = witness_merkle_root_wtxids(&wtxids).expect("witness merkle root");
    let commit = witness_commitment_hash(wroot);
    coinbase_tx_with_outputs(
        locktime,
        &[TestOutput {
            value: 0,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: commit.to_vec(),
        }],
    )
}

fn coinbase_with_witness_commitment_and_p2pk_value(
    locktime: u32,
    value: u64,
    non_coinbase_txs: &[Vec<u8>],
) -> Vec<u8> {
    let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(1 + non_coinbase_txs.len());
    wtxids.push([0u8; 32]);
    for txb in non_coinbase_txs {
        let (_tx, _txid, wtxid, _n) = parse_tx(txb).expect("parse non-coinbase");
        wtxids.push(wtxid);
    }

    let wroot = witness_merkle_root_wtxids(&wtxids).expect("witness merkle root");
    let commit = witness_commitment_hash(wroot);
    coinbase_tx_with_outputs(
        locktime,
        &[
            TestOutput {
                value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: valid_p2pk_covenant_data(),
            },
            TestOutput {
                value: 0,
                covenant_type: COV_TYPE_ANCHOR,
                covenant_data: commit.to_vec(),
            },
        ],
    )
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    assert_eq!(s.len(), 64);
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte");
    }
    out
}

fn biguint_to_bytes32(x: &BigUint) -> [u8; 32] {
    let b = x.to_bytes_be();
    assert!(b.len() <= 32);
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

fn tx_with_one_input_one_output(
    prev_txid: [u8; 32],
    prev_vout: u32,
    out_value: u64,
    out_cov_type: u16,
    out_cov_data: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.push(0x00); // tx_kind
    b.extend_from_slice(&1u64.to_le_bytes());
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    b.extend_from_slice(&prev_txid);
    b.extend_from_slice(&prev_vout.to_le_bytes());
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(1, &mut b); // output_count
    b.extend_from_slice(&out_value.to_le_bytes());
    b.extend_from_slice(&out_cov_type.to_le_bytes());
    crate::compactsize::encode_compact_size(out_cov_data.len() as u64, &mut b);
    b.extend_from_slice(out_cov_data);
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    crate::compactsize::encode_compact_size(1, &mut b); // witness_count
    b.push(SUITE_ID_SENTINEL);
    crate::compactsize::encode_compact_size(0, &mut b); // pubkey_length
    crate::compactsize::encode_compact_size(0, &mut b); // sig_length
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

#[allow(clippy::too_many_arguments)]
fn tx_with_one_input_one_output_with_witness(
    prev_txid: [u8; 32],
    prev_vout: u32,
    out_value: u64,
    out_cov_type: u16,
    out_cov_data: &[u8],
    suite_id: u8,
    pubkey: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.push(0x00); // tx_kind
    b.extend_from_slice(&1u64.to_le_bytes());
    crate::compactsize::encode_compact_size(1, &mut b); // input_count
    b.extend_from_slice(&prev_txid);
    b.extend_from_slice(&prev_vout.to_le_bytes());
    crate::compactsize::encode_compact_size(0, &mut b); // script_sig_len
    b.extend_from_slice(&0u32.to_le_bytes()); // sequence
    crate::compactsize::encode_compact_size(1, &mut b); // output_count
    b.extend_from_slice(&out_value.to_le_bytes());
    b.extend_from_slice(&out_cov_type.to_le_bytes());
    crate::compactsize::encode_compact_size(out_cov_data.len() as u64, &mut b);
    b.extend_from_slice(out_cov_data);
    b.extend_from_slice(&0u32.to_le_bytes()); // locktime
    crate::compactsize::encode_compact_size(1, &mut b); // witness_count
    b.push(suite_id);
    crate::compactsize::encode_compact_size(pubkey.len() as u64, &mut b);
    b.extend_from_slice(pubkey);
    crate::compactsize::encode_compact_size(signature.len() as u64, &mut b);
    b.extend_from_slice(signature);
    crate::compactsize::encode_compact_size(0, &mut b); // da_payload_len
    b
}

fn valid_p2pk_covenant_data() -> Vec<u8> {
    let mut b = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    b[0] = SUITE_ID_ML_DSA_87;
    b
}

fn owner_p2pk_covenant_data_for_vault() -> Vec<u8> {
    let mut b = valid_p2pk_covenant_data();
    b[1] = 0x01;
    b
}

fn sentinel_witness_item() -> crate::tx::WitnessItem {
    crate::tx::WitnessItem {
        suite_id: SUITE_ID_SENTINEL,
        pubkey: vec![],
        signature: vec![],
    }
}

// OpenSSL-backed test signer (non-consensus helper).
struct TestMLDSA87Keypair {
    pkey: *mut openssl_sys::EVP_PKEY,
    pubkey: Vec<u8>,
}

impl Drop for TestMLDSA87Keypair {
    fn drop(&mut self) {
        unsafe {
            if !self.pkey.is_null() {
                openssl_sys::EVP_PKEY_free(self.pkey);
                self.pkey = core::ptr::null_mut();
            }
        }
    }
}

extern "C" {
    fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut core::ffi::c_void,
        name: *const core::ffi::c_char,
        propq: *const core::ffi::c_char,
    ) -> *mut openssl_sys::EVP_PKEY_CTX;
    fn EVP_MD_CTX_new() -> *mut openssl_sys::EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut openssl_sys::EVP_MD_CTX);
    fn EVP_DigestSignInit_ex(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        pctx: *mut *mut openssl_sys::EVP_PKEY_CTX,
        mdname: *const core::ffi::c_char,
        libctx: *mut core::ffi::c_void,
        props: *const core::ffi::c_char,
        pkey: *mut openssl_sys::EVP_PKEY,
        params: *const core::ffi::c_void,
    ) -> core::ffi::c_int;
    fn EVP_DigestSign(
        ctx: *mut openssl_sys::EVP_MD_CTX,
        sigret: *mut core::ffi::c_uchar,
        siglen: *mut usize,
        tbs: *const core::ffi::c_uchar,
        tbslen: usize,
    ) -> core::ffi::c_int;
    fn EVP_PKEY_get_raw_public_key(
        pkey: *const openssl_sys::EVP_PKEY,
        pub_: *mut core::ffi::c_uchar,
        publen: *mut usize,
    ) -> core::ffi::c_int;
}

fn test_mldsa87_keypair() -> Option<TestMLDSA87Keypair> {
    let alg = c"ML-DSA-87";
    unsafe {
        openssl_sys::ERR_clear_error();
        let ctx =
            EVP_PKEY_CTX_new_from_name(core::ptr::null_mut(), alg.as_ptr(), core::ptr::null());
        if ctx.is_null() {
            eprintln!("skip: ML-DSA backend unavailable in current OpenSSL build");
            return None;
        }
        assert!(
            openssl_sys::EVP_PKEY_keygen_init(ctx) > 0,
            "EVP_PKEY_keygen_init failed"
        );
        let mut pkey: *mut openssl_sys::EVP_PKEY = core::ptr::null_mut();
        assert!(
            openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) > 0,
            "EVP_PKEY_keygen failed"
        );
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        assert!(!pkey.is_null(), "nil pkey");

        let mut pubkey = vec![0u8; ML_DSA_87_PUBKEY_BYTES as usize];
        let mut pubkey_len: usize = pubkey.len();
        assert!(
            EVP_PKEY_get_raw_public_key(pkey, pubkey.as_mut_ptr(), &mut pubkey_len) > 0,
            "EVP_PKEY_get_raw_public_key failed"
        );
        assert_eq!(pubkey_len, ML_DSA_87_PUBKEY_BYTES as usize);

        Some(TestMLDSA87Keypair { pkey, pubkey })
    }
}

macro_rules! kp_or_skip {
    () => {{
        match test_mldsa87_keypair() {
            Some(kp) => kp,
            None => return,
        }
    }};
}

fn p2pk_covenant_data_for_pubkey(pubkey: &[u8]) -> Vec<u8> {
    let key_id = sha3_256(pubkey);
    let mut b = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    b[0] = SUITE_ID_ML_DSA_87;
    b[1..33].copy_from_slice(&key_id);
    b
}

fn sign_input_witness(
    tx: &crate::tx::Tx,
    input_index: u32,
    input_value: u64,
    chain_id: [u8; 32],
    kp: &TestMLDSA87Keypair,
) -> crate::tx::WitnessItem {
    let digest = sighash_v1_digest(tx, input_index, input_value, chain_id).expect("sighash");
    unsafe {
        let mctx = EVP_MD_CTX_new();
        assert!(!mctx.is_null(), "EVP_MD_CTX_new failed");
        assert!(
            EVP_DigestSignInit_ex(
                mctx,
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null(),
                kp.pkey,
                core::ptr::null(),
            ) > 0,
            "EVP_DigestSignInit_ex failed"
        );
        let mut sig = vec![0u8; ML_DSA_87_SIG_BYTES as usize];
        let mut sig_len: usize = sig.len();
        assert!(
            EVP_DigestSign(
                mctx,
                sig.as_mut_ptr(),
                &mut sig_len,
                digest.as_ptr(),
                digest.len(),
            ) > 0,
            "EVP_DigestSign failed"
        );
        EVP_MD_CTX_free(mctx);
        assert_eq!(sig_len, ML_DSA_87_SIG_BYTES as usize);
        sig.push(SIGHASH_ALL);

        crate::tx::WitnessItem {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey: kp.pubkey.clone(),
            signature: sig,
        }
    }
}

fn make_keys(count: usize, base: u8) -> Vec<[u8; 32]> {
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        let mut k = [0u8; 32];
        k[0] = base + (i as u8);
        keys.push(k);
    }
    keys
}

fn encode_vault_covenant_data(
    owner_lock_id: [u8; 32],
    threshold: u8,
    keys: &[[u8; 32]],
    whitelist: &[[u8; 32]],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + 1 + 1 + keys.len() * 32 + 2 + whitelist.len() * 32);
    b.extend_from_slice(&owner_lock_id);
    b.push(threshold);
    b.push(keys.len() as u8);
    for k in keys {
        b.extend_from_slice(k);
    }
    b.extend_from_slice(&(whitelist.len() as u16).to_le_bytes());
    for h in whitelist {
        b.extend_from_slice(h);
    }
    b
}

fn encode_multisig_covenant_data(threshold: u8, keys: &[[u8; 32]]) -> Vec<u8> {
    let mut b = Vec::with_capacity(2 + keys.len() * 32);
    b.push(threshold);
    b.push(keys.len() as u8);
    for k in keys {
        b.extend_from_slice(k);
    }
    b
}

fn valid_vault_covenant_data_for_p2pk_output() -> Vec<u8> {
    // Destination (whitelisted) output descriptor.
    let dest = valid_p2pk_covenant_data();
    let h = sha3_256(&crate::vault::output_descriptor_bytes(COV_TYPE_P2PK, &dest));

    // Owner lock id is the hash of a (possibly different) owner output descriptor.
    let owner = owner_p2pk_covenant_data_for_vault();
    let owner_lock_id = sha3_256(&crate::vault::output_descriptor_bytes(
        COV_TYPE_P2PK,
        &owner,
    ));

    encode_vault_covenant_data(owner_lock_id, 1, &make_keys(1, 0x11), &[h])
}

fn encode_htlc_covenant_data(
    hash: [u8; 32],
    lock_mode: u8,
    lock_value: u64,
    claim_key_id: [u8; 32],
    refund_key_id: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_HTLC_COVENANT_DATA as usize);
    out.extend_from_slice(&hash);
    out.push(lock_mode);
    out.extend_from_slice(&lock_value.to_le_bytes());
    out.extend_from_slice(&claim_key_id);
    out.extend_from_slice(&refund_key_id);
    out
}

mod block_basic;
mod covenant_genesis;
mod precompute;
mod tx_parse;
mod tx_validate_worker;
mod utxo_apply;
