use crate::compactsize::read_compact_size;
use crate::constants::*;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::wire_read::Reader;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub tx_kind: u8,
    pub tx_nonce: u64,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
    pub da_commit_core: Option<DaCommitCore>,
    pub da_chunk_core: Option<DaChunkCore>,
    pub witness: Vec<WitnessItem>,
    pub da_payload: Vec<u8>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessItem {
    pub suite_id: u8,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaCommitCore {
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
pub struct DaChunkCore {
    pub da_id: [u8; 32],
    pub chunk_index: u16,
    pub chunk_hash: [u8; 32],
}

pub fn parse_tx(b: &[u8]) -> Result<(Tx, [u8; 32], [u8; 32], usize), TxError> {
    let mut r = Reader::new(b);

    let version = r.read_u32_le()?;

    let tx_kind = r.read_u8()?;
    if tx_kind != 0x00 && tx_kind != 0x01 && tx_kind != 0x02 {
        return Err(TxError::new(ErrorCode::TxErrParse, "unsupported tx_kind"));
    }

    let tx_nonce = r.read_u64_le()?;

    let (in_count, _) = read_compact_size(&mut r)?;
    if in_count > MAX_TX_INPUTS {
        return Err(TxError::new(ErrorCode::TxErrParse, "input_count overflow"));
    }
    let in_count_usize = in_count as usize;

    let mut inputs = Vec::with_capacity(in_count_usize);
    for _ in 0..in_count_usize {
        let prev = r.read_bytes(32)?;
        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(prev);

        let prev_vout = r.read_u32_le()?;

        let (script_sig_len, _) = read_compact_size(&mut r)?;
        if script_sig_len > MAX_SCRIPT_SIG_BYTES {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "script_sig_len overflow",
            ));
        }
        let script_sig_len_usize = script_sig_len as usize;
        let script_sig = r.read_bytes(script_sig_len_usize)?.to_vec();

        let sequence = r.read_u32_le()?;

        inputs.push(TxInput {
            prev_txid,
            prev_vout,
            script_sig,
            sequence,
        });
    }

    let (out_count, _) = read_compact_size(&mut r)?;
    if out_count > MAX_TX_OUTPUTS {
        return Err(TxError::new(ErrorCode::TxErrParse, "output_count overflow"));
    }
    let out_count_usize = out_count as usize;

    let mut outputs = Vec::with_capacity(out_count_usize);
    for _ in 0..out_count_usize {
        let value = r.read_u64_le()?;
        let covenant_type = r.read_u16_le()?;

        let (cov_len_u64, _) = read_compact_size(&mut r)?;
        if cov_len_u64 > usize::MAX as u64 {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "covenant_data_len overflows usize",
            ));
        }
        if cov_len_u64 > MAX_COVENANT_DATA_PER_OUTPUT {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "covenant_data_len exceeds MAX_COVENANT_DATA_PER_OUTPUT",
            ));
        }
        let cov_len = cov_len_u64 as usize;
        let covenant_data = r.read_bytes(cov_len)?.to_vec();

        outputs.push(TxOutput {
            value,
            covenant_type,
            covenant_data,
        });
    }

    let locktime = r.read_u32_le()?;

    let mut da_commit_core: Option<DaCommitCore> = None;
    let mut da_chunk_core: Option<DaChunkCore> = None;
    match tx_kind {
        0x01 => {
            let da_id_bytes = r.read_bytes(32)?;
            let mut da_id = [0u8; 32];
            da_id.copy_from_slice(da_id_bytes);

            let chunk_count = r.read_u16_le()?;
            if chunk_count == 0 || (chunk_count as u64) > MAX_DA_CHUNK_COUNT {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "chunk_count out of range for tx_kind=0x01",
                ));
            }

            let retl_domain_id_bytes = r.read_bytes(32)?;
            let mut retl_domain_id = [0u8; 32];
            retl_domain_id.copy_from_slice(retl_domain_id_bytes);

            let batch_number = r.read_u64_le()?;

            let tx_data_root_bytes = r.read_bytes(32)?;
            let mut tx_data_root = [0u8; 32];
            tx_data_root.copy_from_slice(tx_data_root_bytes);

            let state_root_bytes = r.read_bytes(32)?;
            let mut state_root = [0u8; 32];
            state_root.copy_from_slice(state_root_bytes);

            let withdrawals_root_bytes = r.read_bytes(32)?;
            let mut withdrawals_root = [0u8; 32];
            withdrawals_root.copy_from_slice(withdrawals_root_bytes);

            let batch_sig_suite = r.read_u8()?;

            let (batch_sig_len_u64, _) = read_compact_size(&mut r)?;
            if batch_sig_len_u64 > MAX_DA_MANIFEST_BYTES_PER_TX
                || batch_sig_len_u64 > usize::MAX as u64
            {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "batch_sig_len overflow",
                ));
            }
            let batch_sig = r.read_bytes(batch_sig_len_u64 as usize)?.to_vec();

            da_commit_core = Some(DaCommitCore {
                da_id,
                chunk_count,
                retl_domain_id,
                batch_number,
                tx_data_root,
                state_root,
                withdrawals_root,
                batch_sig_suite,
                batch_sig,
            });
        }
        0x02 => {
            let da_id_bytes = r.read_bytes(32)?;
            let mut da_id = [0u8; 32];
            da_id.copy_from_slice(da_id_bytes);

            let chunk_index = r.read_u16_le()?;
            if (chunk_index as u64) >= MAX_DA_CHUNK_COUNT {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "chunk_index out of range for tx_kind=0x02",
                ));
            }

            let chunk_hash_bytes = r.read_bytes(32)?;
            let mut chunk_hash = [0u8; 32];
            chunk_hash.copy_from_slice(chunk_hash_bytes);

            da_chunk_core = Some(DaChunkCore {
                da_id,
                chunk_index,
                chunk_hash,
            });
        }
        _ => {}
    }

    let core_end = r.offset();

    // Witness section.
    let (witness_count_u64, witness_count_varint_bytes) = read_compact_size(&mut r)?;
    if witness_count_u64 > MAX_WITNESS_ITEMS {
        return Err(TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "witness_count overflow",
        ));
    }
    let witness_count = witness_count_u64 as usize;

    let mut witness_bytes = witness_count_varint_bytes;
    let mut slh_witness_bytes: usize = 0;
    let mut witness = Vec::with_capacity(witness_count);

    for _ in 0..witness_count {
        let suite_id = r.read_u8()?;
        witness_bytes += 1;

        let (pub_len_u64, pub_len_varint_bytes) = read_compact_size(&mut r)?;
        witness_bytes += pub_len_varint_bytes;
        if pub_len_u64 > usize::MAX as u64 {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "pubkey_length overflows usize",
            ));
        }
        let pub_len = pub_len_u64 as usize;
        let pubkey = r.read_bytes(pub_len)?.to_vec();
        witness_bytes += pub_len;

        let (sig_len_u64, sig_len_varint_bytes) = read_compact_size(&mut r)?;
        witness_bytes += sig_len_varint_bytes;
        if sig_len_u64 > usize::MAX as u64 {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "sig_length overflows usize",
            ));
        }
        let sig_len = sig_len_u64 as usize;
        let signature = r.read_bytes(sig_len)?.to_vec();
        witness_bytes += sig_len;

        if witness_bytes > MAX_WITNESS_BYTES_PER_TX {
            return Err(TxError::new(
                ErrorCode::TxErrWitnessOverflow,
                "witness bytes overflow",
            ));
        }
        let item_bytes = 1 + pub_len_varint_bytes + pub_len + sig_len_varint_bytes + sig_len;
        if suite_id == SUITE_ID_SLH_DSA_SHAKE_256F {
            slh_witness_bytes += item_bytes;
            if slh_witness_bytes > MAX_SLH_WITNESS_BYTES_PER_TX {
                return Err(TxError::new(
                    ErrorCode::TxErrWitnessOverflow,
                    "SLH witness bytes overflow",
                ));
            }
        }

        match suite_id {
            SUITE_ID_SENTINEL => {
                let ok = if pub_len == 0 && sig_len == 0 {
                    true
                } else if pub_len == 32 {
                    if sig_len == 1 {
                        signature.first() == Some(&0x01)
                    } else if sig_len >= 3 {
                        if signature.first() != Some(&0x00) {
                            false
                        } else {
                            let pre_len = u16::from_le_bytes(
                                signature[1..3]
                                    .try_into()
                                    .expect("signature[1..3] is 2 bytes"),
                            ) as usize;
                            if (pre_len as u64) < MIN_HTLC_PREIMAGE_BYTES
                                || pre_len as u64 > MAX_HTLC_PREIMAGE_BYTES
                            {
                                false
                            } else {
                                sig_len == 3 + pre_len
                            }
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !ok {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "non-canonical sentinel witness item",
                    ));
                }
            }
            SUITE_ID_ML_DSA_87 => {
                if !(pub_len_u64 == ML_DSA_87_PUBKEY_BYTES && sig_len_u64 == ML_DSA_87_SIG_BYTES) {
                    return Err(TxError::new(
                        ErrorCode::TxErrSigNoncanonical,
                        "non-canonical ML-DSA witness item lengths",
                    ));
                }
            }
            SUITE_ID_SLH_DSA_SHAKE_256F => {
                // Length canonicality is deferred to the spend path where block_height is
                // available; activation must be checked before lengths to preserve
                // deterministic error-priority (Q-CF-18).
            }
            _ => {
                return Err(TxError::new(
                    ErrorCode::TxErrSigAlgInvalid,
                    "unknown suite_id",
                ));
            }
        }

        witness.push(WitnessItem {
            suite_id,
            pubkey,
            signature,
        });
    }

    // DA payload.
    let (da_len_u64, _) = read_compact_size(&mut r)?;
    let mut da_payload: Vec<u8> = Vec::new();
    match tx_kind {
        0x00 => {
            if da_len_u64 != 0 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "da_payload_len must be 0 for tx_kind=0x00",
                ));
            }
        }
        0x01 => {
            if da_len_u64 > MAX_DA_MANIFEST_BYTES_PER_TX || da_len_u64 > usize::MAX as u64 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "da_payload_len out of range for tx_kind=0x01",
                ));
            }
            if da_len_u64 != 0 {
                da_payload = r.read_bytes(da_len_u64 as usize)?.to_vec();
            }
        }
        0x02 => {
            if da_len_u64 == 0 || da_len_u64 > CHUNK_BYTES || da_len_u64 > usize::MAX as u64 {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "da_payload_len out of range for tx_kind=0x02",
                ));
            }
            da_payload = r.read_bytes(da_len_u64 as usize)?.to_vec();
        }
        _ => {
            return Err(TxError::new(ErrorCode::TxErrParse, "unsupported tx_kind"));
        }
    }
    let total_end = r.offset();

    let txid = sha3_256(&b[..core_end]);
    let wtxid = sha3_256(&b[..total_end]);

    let tx = Tx {
        version,
        tx_kind,
        tx_nonce,
        inputs,
        outputs,
        locktime,
        da_commit_core,
        da_chunk_core,
        witness,
        da_payload,
    };

    Ok((tx, txid, wtxid, total_end))
}

pub fn da_core_fields_bytes(tx: &Tx) -> Result<Vec<u8>, TxError> {
    match tx.tx_kind {
        0x00 => Ok(Vec::new()),
        0x01 => {
            let Some(core) = tx.da_commit_core.as_ref() else {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "missing da_commit_core for tx_kind=0x01",
                ));
            };
            let mut out =
                Vec::with_capacity(32 + 2 + 32 + 8 + 32 + 32 + 32 + 1 + 9 + core.batch_sig.len());
            out.extend_from_slice(&core.da_id);
            out.extend_from_slice(&core.chunk_count.to_le_bytes());
            out.extend_from_slice(&core.retl_domain_id);
            out.extend_from_slice(&core.batch_number.to_le_bytes());
            out.extend_from_slice(&core.tx_data_root);
            out.extend_from_slice(&core.state_root);
            out.extend_from_slice(&core.withdrawals_root);
            out.push(core.batch_sig_suite);
            crate::compactsize::encode_compact_size(core.batch_sig.len() as u64, &mut out);
            out.extend_from_slice(&core.batch_sig);
            Ok(out)
        }
        0x02 => {
            let Some(core) = tx.da_chunk_core.as_ref() else {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "missing da_chunk_core for tx_kind=0x02",
                ));
            };
            let mut out = Vec::with_capacity(32 + 2 + 32);
            out.extend_from_slice(&core.da_id);
            out.extend_from_slice(&core.chunk_index.to_le_bytes());
            out.extend_from_slice(&core.chunk_hash);
            Ok(out)
        }
        _ => Err(TxError::new(ErrorCode::TxErrParse, "unsupported tx_kind")),
    }
}

// ---------------------------------------------------------------------------
// Kani bounded model checking proofs
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod verification {
    use super::*;

    /// parse_tx never panics on arbitrary short input — returns Ok or Err.
    /// Buffer is 13 bytes: version(4) + tx_kind(1) + tx_nonce(8) = 13.
    /// This covers the fixed-header prefix; parse always fails before reaching
    /// SHA3 hashing (which requires a fully-parsed tx), keeping SAT tractable.
    #[kani::proof]
    fn verify_parse_tx_no_panic() {
        let buf: [u8; 13] = kani::any();
        let _ = parse_tx(&buf);
    }
}
