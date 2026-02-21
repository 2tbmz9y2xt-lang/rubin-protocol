use rubin_consensus::{
    block_hash, merkle_root_txids, parse_tx, pow_check, retarget_v1, sighash_v1_digest, ErrorCode,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    op: String,

    #[serde(default)]
    tx_hex: String,

    #[serde(default)]
    txids: Vec<String>,

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
