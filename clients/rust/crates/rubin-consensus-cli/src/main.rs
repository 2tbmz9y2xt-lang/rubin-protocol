use rubin_consensus::{
    apply_non_coinbase_tx_basic, block_hash, compact_shortid, merkle_root_txids, parse_tx,
    pow_check, retarget_v1, sighash_v1_digest, validate_block_basic_at_height,
    validate_tx_covenants_genesis, ErrorCode, Outpoint, UtxoEntry,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

#[derive(Deserialize)]
struct Request {
    op: String,

    #[serde(default)]
    tx_hex: String,

    #[serde(default)]
    block_hex: String,

    #[serde(default)]
    txids: Vec<String>,

    #[serde(default)]
    wtxid: String,

    #[serde(default)]
    covenant_type: u16,

    #[serde(default)]
    covenant_data_hex: String,

    #[serde(default)]
    nonce1: u64,

    #[serde(default)]
    nonce2: u64,

    #[serde(default)]
    input_index: u32,

    #[serde(default)]
    input_value: u64,

    #[serde(default)]
    chain_id: String,

    #[serde(default)]
    header_hex: String,

    #[serde(default)]
    target_hex: String,

    #[serde(default)]
    target_old: String,

    #[serde(default)]
    timestamp_first: u64,

    #[serde(default)]
    timestamp_last: u64,

    #[serde(default)]
    expected_prev_hash: String,

    #[serde(default)]
    expected_target: String,

    #[serde(default)]
    utxos: Vec<UtxoJson>,

    #[serde(default)]
    height: u64,

    #[serde(default)]
    block_timestamp: u64,
}

#[derive(Deserialize)]
struct UtxoJson {
    txid: String,
    vout: u32,
    value: u64,
    covenant_type: u16,
    covenant_data: String,
    creation_height: u64,
    created_by_coinbase: bool,
}

#[derive(Serialize)]
struct Response {
    ok: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    wtxid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_root: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    consumed: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    target_new: Option<String>,
}

fn err_code(code: ErrorCode) -> String {
    code.as_str().to_string()
}

fn main() {
    let req: Request = match serde_json::from_reader(std::io::stdin()) {
        Ok(v) => v,
        Err(e) => {
            let resp = Response {
                ok: false,
                err: Some(format!("bad request: {e}")),
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: None,
                consumed: None,
                block_hash: None,
                target_new: None,
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
            return;
        }
    };

    match req.op.as_str() {
        "parse_tx" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            match parse_tx(&tx_bytes) {
                Ok((_tx, txid, wtxid, n)) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: Some(hex::encode(txid)),
                        wtxid: Some(hex::encode(wtxid)),
                        merkle_root: None,
                        digest: None,
                        consumed: Some(n),
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "merkle_root" => {
            let mut txids: Vec<[u8; 32]> = Vec::with_capacity(req.txids.len());
            for h in &req.txids {
                let b = match hex::decode(h) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad txid".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad txid".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                txids.push(a);
            }
            match merkle_root_txids(&txids) {
                Ok(root) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: Some(hex::encode(root)),
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "sighash_v1" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let tx = match parse_tx(&tx_bytes) {
                Ok((tx, _txid, _wtxid, _n)) => tx,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let chain_id_bytes = match hex::decode(req.chain_id) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad chain_id".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            if chain_id_bytes.len() != 32 {
                let resp = Response {
                    ok: false,
                    err: Some("bad chain_id".to_string()),
                    txid: None,
                    wtxid: None,
                    merkle_root: None,
                    digest: None,
                    consumed: None,
                    block_hash: None,
                    target_new: None,
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut chain_id = [0u8; 32];
            chain_id.copy_from_slice(&chain_id_bytes);

            match sighash_v1_digest(&tx, req.input_index, req.input_value, chain_id) {
                Ok(d) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: Some(hex::encode(d)),
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "block_hash" => {
            let header_bytes = match hex::decode(req.header_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad header".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            match block_hash(&header_bytes) {
                Ok(h) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: Some(hex::encode(h)),
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "pow_check" => {
            let header_bytes = match hex::decode(req.header_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad header".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let target_bytes = match hex::decode(req.target_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad target".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            if target_bytes.len() != 32 {
                let resp = Response {
                    ok: false,
                    err: Some("bad target".to_string()),
                    txid: None,
                    wtxid: None,
                    merkle_root: None,
                    digest: None,
                    consumed: None,
                    block_hash: None,
                    target_new: None,
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut target = [0u8; 32];
            target.copy_from_slice(&target_bytes);

            match pow_check(&header_bytes, target) {
                Ok(()) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "retarget_v1" => {
            let old_bytes = match hex::decode(req.target_old) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad target_old".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            if old_bytes.len() != 32 {
                let resp = Response {
                    ok: false,
                    err: Some("bad target_old".to_string()),
                    txid: None,
                    wtxid: None,
                    merkle_root: None,
                    digest: None,
                    consumed: None,
                    block_hash: None,
                    target_new: None,
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut old = [0u8; 32];
            old.copy_from_slice(&old_bytes);

            match retarget_v1(old, req.timestamp_first, req.timestamp_last) {
                Ok(new_t) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: Some(hex::encode(new_t)),
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "block_basic_check" => {
            let block_bytes = match hex::decode(req.block_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad block".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let expected_prev = if req.expected_prev_hash.is_empty() {
                None
            } else {
                let b = match hex::decode(req.expected_prev_hash) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad expected_prev_hash".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad expected_prev_hash".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                Some(h)
            };

            let expected_target = if req.expected_target.is_empty() {
                None
            } else {
                let b = match hex::decode(req.expected_target) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad expected_target".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if b.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad expected_target".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                Some(h)
            };

            match validate_block_basic_at_height(
                &block_bytes,
                expected_prev,
                expected_target,
                req.height,
            ) {
                Ok(summary) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: Some(hex::encode(summary.block_hash)),
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "covenant_genesis_check" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let tx = match parse_tx(&tx_bytes) {
                Ok((tx, _txid, _wtxid, _n)) => tx,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            match validate_tx_covenants_genesis(&tx) {
                Ok(()) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "utxo_apply_basic" => {
            let tx_bytes = match hex::decode(req.tx_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let (tx, txid, _wtxid, _n) = match parse_tx(&tx_bytes) {
                Ok(v) => v,
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };

            let mut utxo_set: HashMap<Outpoint, UtxoEntry> =
                HashMap::with_capacity(req.utxos.len());
            for u in &req.utxos {
                let txid_raw = match hex::decode(&u.txid) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad utxo txid".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };
                if txid_raw.len() != 32 {
                    let resp = Response {
                        ok: false,
                        err: Some("bad utxo txid".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
                let cov_data = match hex::decode(&u.covenant_data) {
                    Ok(v) => v,
                    Err(_) => {
                        let resp = Response {
                            ok: false,
                            err: Some("bad utxo covenant_data".to_string()),
                            txid: None,
                            wtxid: None,
                            merkle_root: None,
                            digest: None,
                            consumed: None,
                            block_hash: None,
                            target_new: None,
                        };
                        let _ = serde_json::to_writer(std::io::stdout(), &resp);
                        return;
                    }
                };

                let mut op_txid = [0u8; 32];
                op_txid.copy_from_slice(&txid_raw);
                utxo_set.insert(
                    Outpoint {
                        txid: op_txid,
                        vout: u.vout,
                    },
                    UtxoEntry {
                        value: u.value,
                        covenant_type: u.covenant_type,
                        covenant_data: cov_data,
                        creation_height: u.creation_height,
                        created_by_coinbase: u.created_by_coinbase,
                    },
                );
            }

            match apply_non_coinbase_tx_basic(&tx, txid, &utxo_set, req.height, req.block_timestamp)
            {
                Ok(_summary) => {
                    let resp = Response {
                        ok: true,
                        err: None,
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
                Err(e) => {
                    let resp = Response {
                        ok: false,
                        err: Some(err_code(e.code)),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                }
            }
        }
        "compact_shortid" => {
            let wtxid_bytes = match hex::decode(req.wtxid) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad wtxid".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            if wtxid_bytes.len() != 32 {
                let resp = Response {
                    ok: false,
                    err: Some("bad wtxid".to_string()),
                    txid: None,
                    wtxid: None,
                    merkle_root: None,
                    digest: None,
                    consumed: None,
                    block_hash: None,
                    target_new: None,
                };
                let _ = serde_json::to_writer(std::io::stdout(), &resp);
                return;
            }
            let mut wtxid = [0u8; 32];
            wtxid.copy_from_slice(&wtxid_bytes);
            let sid = compact_shortid(wtxid, req.nonce1, req.nonce2);
            let resp = Response {
                ok: true,
                err: None,
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: Some(hex::encode(sid)),
                consumed: None,
                block_hash: None,
                target_new: None,
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "output_descriptor_bytes" => {
            let cov_data = match hex::decode(req.covenant_data_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad covenant_data_hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let desc = output_descriptor_bytes(req.covenant_type, &cov_data);
            let resp = Response {
                ok: true,
                err: None,
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: Some(hex::encode(desc)),
                consumed: None,
                block_hash: None,
                target_new: None,
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        "output_descriptor_hash" => {
            let cov_data = match hex::decode(req.covenant_data_hex) {
                Ok(v) => v,
                Err(_) => {
                    let resp = Response {
                        ok: false,
                        err: Some("bad covenant_data_hex".to_string()),
                        txid: None,
                        wtxid: None,
                        merkle_root: None,
                        digest: None,
                        consumed: None,
                        block_hash: None,
                        target_new: None,
                    };
                    let _ = serde_json::to_writer(std::io::stdout(), &resp);
                    return;
                }
            };
            let desc = output_descriptor_bytes(req.covenant_type, &cov_data);
            let mut hasher = Sha3_256::new();
            hasher.update(desc);
            let h = hasher.finalize();
            let resp = Response {
                ok: true,
                err: None,
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: Some(hex::encode(h)),
                consumed: None,
                block_hash: None,
                target_new: None,
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
        _ => {
            let resp = Response {
                ok: false,
                err: Some("unknown op".to_string()),
                txid: None,
                wtxid: None,
                merkle_root: None,
                digest: None,
                consumed: None,
                block_hash: None,
                target_new: None,
            };
            let _ = serde_json::to_writer(std::io::stdout(), &resp);
        }
    }
}

fn output_descriptor_bytes(covenant_type: u16, covenant_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 9 + covenant_data.len());
    out.extend_from_slice(&covenant_type.to_le_bytes());
    out.extend_from_slice(&encode_compact_size(covenant_data.len() as u64));
    out.extend_from_slice(covenant_data);
    out
}

fn encode_compact_size(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut out = vec![0xfd, 0, 0];
        out[1..3].copy_from_slice(&(n as u16).to_le_bytes());
        out
    } else if n <= 0xffff_ffff {
        let mut out = vec![0xfe, 0, 0, 0, 0];
        out[1..5].copy_from_slice(&(n as u32).to_le_bytes());
        out
    } else {
        let mut out = vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0];
        out[1..9].copy_from_slice(&n.to_le_bytes());
        out
    }
}
