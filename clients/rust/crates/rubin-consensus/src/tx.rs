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

/// Internal split parser used by `parse_tx` and helper/property tests.
///
/// Callers that need stable identifiers must hash `b[..core_end]` for `txid`
/// and `b[..total_end]` for `wtxid`; this helper only parses wire structure.
pub(crate) fn parse_tx_without_hashes(b: &[u8]) -> Result<(Tx, usize, usize), TxError> {
    let mut r = Reader::new(b);
    let (version, tx_kind, tx_nonce) = parse_tx_prefix(&mut r)?;
    let inputs = parse_tx_inputs(&mut r)?;
    let outputs = parse_tx_outputs(&mut r)?;
    let locktime = r.read_u32_le()?;
    let (da_commit_core, da_chunk_core) = parse_da_core(&mut r, tx_kind)?;
    let core_end = r.offset();
    let witness = parse_witnesses(&mut r)?;
    let da_payload = parse_da_payload(&mut r, tx_kind)?;
    let total_end = r.offset();

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

    Ok((tx, core_end, total_end))
}

fn parse_tx_prefix(r: &mut Reader<'_>) -> Result<(u32, u8, u64), TxError> {
    let version = r.read_u32_le()?;
    if version != TX_WIRE_VERSION {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "unsupported tx version",
        ));
    }
    let tx_kind = r.read_u8()?;
    if tx_kind != 0x00 && tx_kind != 0x01 && tx_kind != 0x02 {
        return Err(TxError::new(ErrorCode::TxErrParse, "unsupported tx_kind"));
    }
    let tx_nonce = r.read_u64_le()?;
    Ok((version, tx_kind, tx_nonce))
}

fn parse_tx_inputs(r: &mut Reader<'_>) -> Result<Vec<TxInput>, TxError> {
    let (in_count, _) = read_compact_size(r)?;
    if in_count > MAX_TX_INPUTS {
        return Err(TxError::new(ErrorCode::TxErrParse, "input_count overflow"));
    }
    let mut inputs = Vec::with_capacity(in_count as usize);
    for _ in 0..in_count as usize {
        inputs.push(parse_tx_input(r)?);
    }
    Ok(inputs)
}

fn parse_tx_input(r: &mut Reader<'_>) -> Result<TxInput, TxError> {
    let prev_txid = read_32(r)?;
    let prev_vout = r.read_u32_le()?;
    let (script_sig_len, _) = read_compact_size(r)?;
    if script_sig_len > MAX_SCRIPT_SIG_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "script_sig_len overflow",
        ));
    }
    let script_sig = r.read_bytes(script_sig_len as usize)?.to_vec();
    let sequence = r.read_u32_le()?;
    Ok(TxInput {
        prev_txid,
        prev_vout,
        script_sig,
        sequence,
    })
}

fn parse_tx_outputs(r: &mut Reader<'_>) -> Result<Vec<TxOutput>, TxError> {
    let (out_count, _) = read_compact_size(r)?;
    if out_count > MAX_TX_OUTPUTS {
        return Err(TxError::new(ErrorCode::TxErrParse, "output_count overflow"));
    }
    let mut outputs = Vec::with_capacity(out_count as usize);
    for _ in 0..out_count as usize {
        outputs.push(parse_tx_output(r)?);
    }
    Ok(outputs)
}

fn parse_tx_output(r: &mut Reader<'_>) -> Result<TxOutput, TxError> {
    let value = r.read_u64_le()?;
    let covenant_type = r.read_u16_le()?;
    let (cov_len_u64, _) = read_compact_size(r)?;
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
    let covenant_data = r.read_bytes(cov_len_u64 as usize)?.to_vec();
    Ok(TxOutput {
        value,
        covenant_type,
        covenant_data,
    })
}

fn parse_da_core(
    r: &mut Reader<'_>,
    tx_kind: u8,
) -> Result<(Option<DaCommitCore>, Option<DaChunkCore>), TxError> {
    match tx_kind {
        0x01 => Ok((Some(parse_da_commit_core(r)?), None)),
        0x02 => Ok((None, Some(parse_da_chunk_core(r)?))),
        _ => Ok((None, None)),
    }
}

fn parse_da_commit_core(r: &mut Reader<'_>) -> Result<DaCommitCore, TxError> {
    let da_id = read_32(r)?;
    let chunk_count = read_da_commit_chunk_count(r)?;
    let fields = read_da_commit_fields(r)?;
    let batch_sig_suite = r.read_u8()?;
    let batch_sig = read_da_batch_sig(r)?;
    Ok(DaCommitCore {
        da_id,
        chunk_count,
        retl_domain_id: fields.retl_domain_id,
        batch_number: fields.batch_number,
        tx_data_root: fields.tx_data_root,
        state_root: fields.state_root,
        withdrawals_root: fields.withdrawals_root,
        batch_sig_suite,
        batch_sig,
    })
}

struct DaCommitFields {
    retl_domain_id: [u8; 32],
    batch_number: u64,
    tx_data_root: [u8; 32],
    state_root: [u8; 32],
    withdrawals_root: [u8; 32],
}

fn read_da_commit_chunk_count(r: &mut Reader<'_>) -> Result<u16, TxError> {
    let chunk_count = r.read_u16_le()?;
    if chunk_count == 0 || (chunk_count as u64) > MAX_DA_CHUNK_COUNT {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "chunk_count out of range for tx_kind=0x01",
        ));
    }
    Ok(chunk_count)
}

fn read_da_commit_fields(r: &mut Reader<'_>) -> Result<DaCommitFields, TxError> {
    Ok(DaCommitFields {
        retl_domain_id: read_32(r)?,
        batch_number: r.read_u64_le()?,
        tx_data_root: read_32(r)?,
        state_root: read_32(r)?,
        withdrawals_root: read_32(r)?,
    })
}

fn read_da_batch_sig(r: &mut Reader<'_>) -> Result<Vec<u8>, TxError> {
    let (batch_sig_len_u64, _) = read_compact_size(r)?;
    if batch_sig_len_u64 > MAX_DA_MANIFEST_BYTES_PER_TX || batch_sig_len_u64 > usize::MAX as u64 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "batch_sig_len overflow",
        ));
    }
    Ok(r.read_bytes(batch_sig_len_u64 as usize)?.to_vec())
}

fn parse_da_chunk_core(r: &mut Reader<'_>) -> Result<DaChunkCore, TxError> {
    let da_id = read_32(r)?;
    let chunk_index = r.read_u16_le()?;
    if (chunk_index as u64) >= MAX_DA_CHUNK_COUNT {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "chunk_index out of range for tx_kind=0x02",
        ));
    }
    let chunk_hash = read_32(r)?;
    Ok(DaChunkCore {
        da_id,
        chunk_index,
        chunk_hash,
    })
}

fn parse_witnesses(r: &mut Reader<'_>) -> Result<Vec<WitnessItem>, TxError> {
    let (witness_count_u64, witness_count_varint_bytes) = read_compact_size(r)?;
    if witness_count_u64 > MAX_WITNESS_ITEMS {
        return Err(TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "witness_count overflow",
        ));
    }
    let mut witness_bytes = witness_count_varint_bytes;
    let mut witness = Vec::with_capacity(witness_count_u64 as usize);
    for _ in 0..witness_count_u64 as usize {
        witness.push(parse_witness_item(r, &mut witness_bytes)?);
    }
    Ok(witness)
}

fn parse_witness_item(
    r: &mut Reader<'_>,
    witness_bytes: &mut usize,
) -> Result<WitnessItem, TxError> {
    let suite_id = r.read_u8()?;
    *witness_bytes += 1;
    let (pub_len_u64, pubkey) =
        read_witness_bytes(r, witness_bytes, "pubkey_length overflows usize")?;
    let (sig_len_u64, signature) =
        read_witness_bytes(r, witness_bytes, "sig_length overflows usize")?;
    validate_witness_item_ordered(
        suite_id,
        pub_len_u64,
        sig_len_u64,
        *witness_bytes,
        &signature,
    )?;
    Ok(WitnessItem {
        suite_id,
        pubkey,
        signature,
    })
}

fn read_witness_bytes(
    r: &mut Reader<'_>,
    witness_bytes: &mut usize,
    overflow_msg: &'static str,
) -> Result<(u64, Vec<u8>), TxError> {
    let (len_u64, len_varint_bytes) = read_compact_size(r)?;
    *witness_bytes += len_varint_bytes;
    let len = checked_usize_len(len_u64, overflow_msg)?;
    let bytes = r.read_bytes(len)?.to_vec();
    *witness_bytes += len;
    Ok((len_u64, bytes))
}

fn checked_usize_len(len: u64, msg: &'static str) -> Result<usize, TxError> {
    if len > usize::MAX as u64 {
        return Err(TxError::new(ErrorCode::TxErrParse, msg));
    }
    Ok(len as usize)
}

fn validate_witness_item_ordered(
    suite_id: u8,
    pub_len_u64: u64,
    sig_len_u64: u64,
    witness_bytes: usize,
    signature: &[u8],
) -> Result<(), TxError> {
    if suite_id != SUITE_ID_SENTINEL && sig_len_u64 == 0 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "missing sighash_type byte",
        ));
    }
    if witness_bytes > MAX_WITNESS_BYTES_PER_TX {
        return Err(TxError::new(
            ErrorCode::TxErrWitnessOverflow,
            "witness bytes overflow",
        ));
    }
    validate_witness_item_shape(suite_id, pub_len_u64, sig_len_u64, signature)
}

fn validate_witness_item_shape(
    suite_id: u8,
    pub_len_u64: u64,
    sig_len_u64: u64,
    signature: &[u8],
) -> Result<(), TxError> {
    match suite_id {
        SUITE_ID_SENTINEL => validate_sentinel_witness(pub_len_u64 as usize, signature),
        SUITE_ID_ML_DSA_87
            if !(pub_len_u64 == ML_DSA_87_PUBKEY_BYTES
                && sig_len_u64 == ML_DSA_87_SIG_BYTES + 1) =>
        {
            Err(TxError::new(
                ErrorCode::TxErrSigNoncanonical,
                "non-canonical ML-DSA witness item lengths",
            ))
        }
        SUITE_ID_SIMPLICITY_ENVELOPE if pub_len_u64 != 0 => Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-canonical Simplicity envelope witness item",
        )),
        SUITE_ID_SIMPLICITY_ENVELOPE => validate_simplicity_envelope_signature(signature),
        _ => Ok(()),
    }
}

/// Structurally validates a §5.4 Simplicity envelope witness signature, byte-for-byte
/// with the merged Go `parseSimplicityEnvelopeSignature`: the trailing sighash byte is
/// dropped, then version(0x01) + compactSize program + compactSize witness must consume
/// the envelope exactly, within the canonical size bounds.
fn validate_simplicity_envelope_signature(signature: &[u8]) -> Result<(), TxError> {
    if signature.len() < 2 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-canonical Simplicity envelope witness item",
        ));
    }
    let envelope = &signature[..signature.len() - 1];
    if envelope.len() > MAX_SIMPLICITY_ENVELOPE_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "Simplicity envelope too large",
        ));
    }
    let mut r = Reader::new(envelope);
    if r.read_u8()? != 0x01 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-canonical Simplicity envelope witness item",
        ));
    }
    let (program_len_u64, _) = read_compact_size(&mut r)?;
    if program_len_u64 > MAX_SIMPLICITY_PROGRAM_BYTES {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "Simplicity program too large",
        ));
    }
    r.read_bytes(program_len_u64 as usize)?;
    let (witness_len_u64, _) = read_compact_size(&mut r)?;
    // `isize::MAX` == Go's `math.MaxInt` on every target: byte-identical, and blocks a 32-bit `as usize` truncation.
    if witness_len_u64 > isize::MAX as u64 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "Simplicity witness_len overflows int",
        ));
    }
    r.read_bytes(witness_len_u64 as usize)?;
    if r.offset() != envelope.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-canonical Simplicity envelope witness item",
        ));
    }
    Ok(())
}

fn validate_sentinel_witness(pub_len: usize, signature: &[u8]) -> Result<(), TxError> {
    if is_canonical_sentinel_witness(pub_len, signature) {
        return Ok(());
    }
    Err(TxError::new(
        ErrorCode::TxErrParse,
        "non-canonical sentinel witness item",
    ))
}

fn is_canonical_sentinel_witness(pub_len: usize, signature: &[u8]) -> bool {
    match (pub_len, signature.len()) {
        (0, 0) => true,
        (32, 1) => signature.first() == Some(&0x01),
        (32, sig_len) if sig_len >= 3 => is_canonical_htlc_claim_signature(signature),
        _ => false,
    }
}

fn is_canonical_htlc_claim_signature(signature: &[u8]) -> bool {
    if signature.first() != Some(&0x00) {
        return false;
    }
    let Some(len_bytes) = signature.get(1..3) else {
        return false;
    };
    let Ok(len_bytes) = <[u8; 2]>::try_from(len_bytes) else {
        return false;
    };
    let pre_len = u16::from_le_bytes(len_bytes) as usize;
    (MIN_HTLC_PREIMAGE_BYTES..=MAX_HTLC_PREIMAGE_BYTES).contains(&(pre_len as u64))
        && signature.len() == 3 + pre_len
}

fn parse_da_payload(r: &mut Reader<'_>, tx_kind: u8) -> Result<Vec<u8>, TxError> {
    let (da_len_u64, _) = read_compact_size(r)?;
    match tx_kind {
        0x00 => parse_standard_da_payload(da_len_u64),
        0x01 => parse_da_commit_payload(r, da_len_u64),
        0x02 => parse_da_chunk_payload(r, da_len_u64),
        _ => Err(TxError::new(ErrorCode::TxErrParse, "unsupported tx_kind")),
    }
}

fn parse_standard_da_payload(da_len_u64: u64) -> Result<Vec<u8>, TxError> {
    if da_len_u64 != 0 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "da_payload_len must be 0 for tx_kind=0x00",
        ));
    }
    Ok(Vec::new())
}

fn parse_da_commit_payload(r: &mut Reader<'_>, da_len_u64: u64) -> Result<Vec<u8>, TxError> {
    if da_len_u64 > MAX_DA_MANIFEST_BYTES_PER_TX || da_len_u64 > usize::MAX as u64 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "da_payload_len out of range for tx_kind=0x01",
        ));
    }
    Ok(r.read_bytes(da_len_u64 as usize)?.to_vec())
}

fn parse_da_chunk_payload(r: &mut Reader<'_>, da_len_u64: u64) -> Result<Vec<u8>, TxError> {
    if da_len_u64 == 0 || da_len_u64 > CHUNK_BYTES || da_len_u64 > usize::MAX as u64 {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "da_payload_len out of range for tx_kind=0x02",
        ));
    }
    Ok(r.read_bytes(da_len_u64 as usize)?.to_vec())
}

fn read_32(r: &mut Reader<'_>) -> Result<[u8; 32], TxError> {
    let bytes = r.read_bytes(32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub fn parse_tx(b: &[u8]) -> Result<(Tx, [u8; 32], [u8; 32], usize), TxError> {
    let (tx, core_end, total_end) = parse_tx_without_hashes(b)?;
    let txid = sha3_256(&b[..core_end]);
    let wtxid = sha3_256(&b[..total_end]);
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
    /// This covers the public parser entrypoint before variable-length fields.
    #[kani::proof]
    #[kani::unwind(1)]
    fn verify_parse_tx_no_panic() {
        let buf: [u8; 13] = kani::any();
        let _ = parse_tx(&buf);
    }
}
