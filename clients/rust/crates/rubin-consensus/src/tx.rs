use crate::compactsize::read_compact_size;
use crate::constants::*;
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::wire_read::Reader;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxV2 {
    pub version: u32,
    pub tx_kind: u8,
    pub tx_nonce: u64,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
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

pub fn parse_tx_v2(b: &[u8]) -> Result<(TxV2, [u8; 32], [u8; 32], usize), TxError> {
    let mut r = Reader::new(b);

    let version = r.read_u32_le()?;
    if version != TX_WIRE_VERSION {
        return Err(TxError::new(ErrorCode::TxErrParse, "invalid tx version"));
    }

    let tx_kind = r.read_u8()?;
    if tx_kind != 0x00 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "unsupported tx_kind (genesis)",
        ));
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
        let cov_len = cov_len_u64 as usize;
        let covenant_data = r.read_bytes(cov_len)?.to_vec();

        outputs.push(TxOutput {
            value,
            covenant_type,
            covenant_data,
        });
    }

    let locktime = r.read_u32_le()?;
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

        match suite_id {
            SUITE_ID_SENTINEL => {
                if pub_len != 0 || sig_len != 0 {
                    return Err(TxError::new(
                        ErrorCode::TxErrParse,
                        "non-canonical sentinel witness item",
                    ));
                }
            }
            SUITE_ID_ML_DSA_87 => {
                if pub_len_u64 != ML_DSA_87_PUBKEY_BYTES || sig_len_u64 != ML_DSA_87_SIG_BYTES {
                    return Err(TxError::new(
                        ErrorCode::TxErrSigNoncanonical,
                        "non-canonical ML-DSA witness item lengths",
                    ));
                }
            }
            SUITE_ID_SLH_DSA_SHAKE_256F => {
                if pub_len_u64 != SLH_DSA_SHAKE_256F_PUBKEY_BYTES
                    || sig_len_u64 == 0
                    || sig_len_u64 > MAX_SLH_DSA_SIG_BYTES
                {
                    return Err(TxError::new(
                        ErrorCode::TxErrSigNoncanonical,
                        "non-canonical SLH-DSA witness item lengths",
                    ));
                }
            }
            _ => {
                return Err(TxError::new(
                    ErrorCode::TxErrSigAlgInvalid,
                    "unknown suite_id",
                ));
            }
        }

        if witness_bytes > MAX_WITNESS_BYTES_PER_TX {
            return Err(TxError::new(
                ErrorCode::TxErrWitnessOverflow,
                "witness bytes overflow",
            ));
        }

        witness.push(WitnessItem {
            suite_id,
            pubkey,
            signature,
        });
    }

    // DA payload (genesis tx_kind=0x00 forbids any payload bytes; the length prefix is still present).
    let (da_len_u64, _) = read_compact_size(&mut r)?;
    if da_len_u64 != 0 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "da_payload_len must be 0 for tx_kind=0x00",
        ));
    }
    let total_end = r.offset();

    let txid = sha3_256(&b[..core_end]);
    let wtxid = sha3_256(&b[..total_end]);

    let tx = TxV2 {
        version,
        tx_kind,
        tx_nonce,
        inputs,
        outputs,
        locktime,
        witness,
        da_payload: Vec::new(),
    };

    Ok((tx, txid, wtxid, total_end))
}
