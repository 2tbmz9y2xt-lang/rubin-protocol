use core::fmt;
use std::sync::OnceLock;

use crate::constants::{ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES};
use sha2::{compress256, digest::generic_array::GenericArray};
use sha3::{Digest, Sha3_256};

pub const SEMANTICS_VERSION: u32 = 1;
pub const MAX_PROGRAM_BYTES: usize = 16_384;
pub const MAX_EXEC_COST: u64 = 400_000;
pub const STEP_COST: u64 = 1;
pub const COST_MODEL_SEMANTICS_VERSION: u32 = 2;
pub const JETS_REGISTRY_SEMANTICS_VERSION: u32 = 2;
pub const INTRINSIC_READ_COST: u64 = 1;
pub const INTRINSIC_MISS_COST: u64 = 1;
pub const DESCRIPTOR_HASH_BASE_COST: u64 = 64;
pub const DESCRIPTOR_HASH_BYTE_COST: u64 = 1;
pub const MAX_FRAME_BYTES: u64 = 65_536;
pub const MAX_LIVE_MEMORY_BYTES: u64 = 1_048_576;
pub const SHA3_256_JET_BASE_COST: u64 = 64;
pub const MLDSA87_VERIFY_JET_COST: u64 = 50_000;
pub const MLDSA87_JET_PUBKEY_BYTES: usize = ML_DSA_87_PUBKEY_BYTES as usize;
pub const MLDSA87_JET_SIG_BYTES: usize = ML_DSA_87_SIG_BYTES as usize;
const DATA_JET_FLAT_COST: u64 = 1;
const BYTES_JET_CHUNK_LEN: u64 = 32;
pub use crate::txcontext::Uint128;
#[rustfmt::skip]
pub const PROGRAM_ENCODING_HASH: [u8; 32] = [
    0x27, 0xe5, 0xad, 0x52, 0x1e, 0xfd, 0xf9, 0xd1, 0x85, 0xc1, 0xc9, 0x2a, 0x3a, 0x1a, 0x4a, 0xac, 0xc9, 0x27, 0x6c, 0x2a, 0x5b, 0x1b, 0x85, 0x18, 0xce, 0x25, 0xc8, 0xc9, 0x73, 0xa3, 0x8a, 0xdc,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub enum ErrorCode { Decode, ProgramTooLarge, CmrMismatch, JetDisallowed, BudgetExceeded, Rejected }

#[rustfmt::skip]
impl ErrorCode { pub fn as_str(self) -> &'static str { match self { Self::Decode => "TX_ERR_SIMPLICITY_DECODE", Self::ProgramTooLarge => "TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE", Self::CmrMismatch => "TX_ERR_SIMPLICITY_CMR_MISMATCH", Self::JetDisallowed => "TX_ERR_SIMPLICITY_JET_DISALLOWED", Self::BudgetExceeded => "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED", Self::Rejected => "TX_ERR_SIMPLICITY_REJECTED" } } }

#[derive(Clone, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct Error { pub code: ErrorCode }

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())
    }
}

impl std::error::Error for Error {}

/// Applies the shared Simplicity execution budget cap. Mirrors Go
/// `simplicity.ChargeCost` (budget failure caps the meter at `MAX_EXEC_COST`).
pub fn charge_cost(current: u64, cost: u64) -> Result<u64, Error> {
    if current > MAX_EXEC_COST || cost > MAX_EXEC_COST - current {
        return Err(Error {
            code: ErrorCode::BudgetExceeded,
        });
    }
    Ok(current + cost)
}

/// Returns the in-range descriptor_hash access cost. Mirrors Go
/// `simplicity.DescriptorHashAccessCost`.
pub fn descriptor_hash_access_cost(descriptor_len: u64) -> Result<u64, Error> {
    if DESCRIPTOR_HASH_BYTE_COST != 0
        && descriptor_len > (u64::MAX - DESCRIPTOR_HASH_BASE_COST) / DESCRIPTOR_HASH_BYTE_COST
    {
        return Err(Error {
            code: ErrorCode::BudgetExceeded,
        });
    }
    charge_cost(
        0,
        DESCRIPTOR_HASH_BASE_COST + DESCRIPTOR_HASH_BYTE_COST * descriptor_len,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct DecodeOptions { pub semantics_version: u32, pub covenant_program_cmr: Option<[u8; 32]> }

#[derive(Clone, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct Program { pub cmr: [u8; 32], pub jet: Option<Jet>, pub needs_witness: bool, max_witness_len: usize, witness_kind: WitnessKind, eval_steps: u64, decoded: bool, has_jet: bool, jet_key: Option<JetKey>, frame_bit_widths: Vec<u64> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct Jet { pub id: u16, pub sub_op: u8, pub name: &'static str, pub selector_bit_len: usize, pub selector_padded: &'static [u8], pub cmr: [u8; 32] }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[rustfmt::skip]
pub struct EvalResult { pub accepted: bool, pub cost: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct EvalError { pub code: ErrorCode, pub result: EvalResult }

#[rustfmt::skip]
impl EvalError {
    fn new(code: ErrorCode) -> Self { Self { code, result: EvalResult::default() } }
    fn with_result(code: ErrorCode, result: EvalResult) -> Self { Self { code, result } }
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())
    }
}

impl std::error::Error for EvalError {}

#[derive(Default)]
#[rustfmt::skip]
pub struct EvalOptions<'a> { pub jet_evaluator: Option<&'a dyn Fn(Jet) -> Result<EvalResult, EvalError>> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct Sha3DigestJetResult { pub digest: [u8; 32], pub cost: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct Mldsa87VerifyJetResult { pub verified: bool, pub cost: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct U64JetResult { pub value: u64, pub accepted: bool, pub cost: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct U128JetResult { pub value: Uint128, pub accepted: bool, pub cost: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct OrderingJetResult { pub ordering: core::cmp::Ordering, pub cost: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct BoolJetResult { pub value: bool, pub cost: u64 }

#[derive(Clone, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct BytesJetResult { pub bytes: Vec<u8>, pub accepted: bool, pub cost: u64 }

#[rustfmt::skip]
pub type Mldsa87Digest32Verifier<'a> = dyn Fn(&[u8], &[u8], [u8; 32]) -> Result<bool, EvalError> + 'a;

#[rustfmt::skip]
#[derive(Clone, Copy)]
struct JetRow { id: u16, sub_op: u8, name: &'static str, selector_bit_len: usize, selector_padded: &'static [u8], cmr: &'static str, signature: &'static str }

#[derive(Clone, Copy)]
#[rustfmt::skip]
struct CostModelRow { jet: JetKey, formula: CostFormula, param: u64 }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[rustfmt::skip]
enum CostFormula { Constant, BasePlusLen, OnePlusCeilLen32 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
enum WitnessKind { None, Bool }

type JetKey = (u16, u8);

#[rustfmt::skip]
pub fn decode(program: &[u8], witness: &[u8], opts: DecodeOptions) -> Result<Program, Error> {
    if program.len() > MAX_PROGRAM_BYTES { return Err(Error { code: ErrorCode::ProgramTooLarge }); }
    let mut decoded = decode_program(program)?;
    if opts.covenant_program_cmr.is_some_and(|want| decoded.cmr != want) { return Err(Error { code: ErrorCode::CmrMismatch }); }
    if witness.len() > decoded.max_witness_len || !witness_allowed(decoded.witness_kind, opts.semantics_version, witness) { return Err(Error { code: ErrorCode::Decode }); }
    decoded.decoded = true;
    Ok(decoded)
}

#[rustfmt::skip]
pub fn lookup_jet(id: u16, sub_op: u8) -> Option<Jet> {
    static JETS: OnceLock<Vec<Jet>> = OnceLock::new();
    JETS.get_or_init(|| { validate_jet_registry_rows(JET_ROWS).expect("valid checked-in Rubin jet registry rows"); JET_ROWS.iter().map(|row| { let cmr = hex32(row.cmr).expect("valid checked-in Rubin jet CMR hex"); Jet { id: row.id, sub_op: row.sub_op, name: row.name, selector_bit_len: row.selector_bit_len, selector_padded: row.selector_padded, cmr } }).collect() }).iter().copied().find(|jet| (jet.id, jet.sub_op) == (id, sub_op))
}

#[rustfmt::skip]
pub fn evaluate_sha3_256_jet(message: &[u8]) -> Sha3DigestJetResult {
    let message_len = u64::try_from(message.len()).unwrap_or(u64::MAX);
    let cost = SHA3_256_JET_BASE_COST.saturating_add(message_len);
    Sha3DigestJetResult { digest: crate::hash::sha3_256(message), cost }
}

#[rustfmt::skip]
pub fn evaluate_mldsa87_verify_jet(pubkey: &[u8], signature: &[u8], digest32: [u8; 32], verifier: Option<&Mldsa87Digest32Verifier<'_>>) -> Result<Mldsa87VerifyJetResult, EvalError> {
    let result = Mldsa87VerifyJetResult { verified: false, cost: MLDSA87_VERIFY_JET_COST };
    if pubkey.len() != MLDSA87_JET_PUBKEY_BYTES || signature.len() != MLDSA87_JET_SIG_BYTES { return Ok(result); }
    let verifier = verifier.ok_or_else(|| EvalError::with_result(ErrorCode::JetDisallowed, result.into_eval_result()))?;
    let verified = verifier(pubkey, signature, digest32).map_err(|err| EvalError::with_result(err.code, result.into_eval_result()))?;
    Ok(Mldsa87VerifyJetResult { verified, ..result })
}

#[rustfmt::skip]
pub fn evaluate_u64_checked_add_jet(a: u64, b: u64) -> U64JetResult {
    match a.checked_add(b) {
        Some(value) => U64JetResult { value, accepted: true, cost: DATA_JET_FLAT_COST },
        None => U64JetResult { value: 0, accepted: false, cost: DATA_JET_FLAT_COST },
    }
}

#[rustfmt::skip]
pub fn evaluate_u64_checked_sub_jet(a: u64, b: u64) -> U64JetResult {
    match a.checked_sub(b) {
        Some(value) => U64JetResult { value, accepted: true, cost: DATA_JET_FLAT_COST },
        None => U64JetResult { value: 0, accepted: false, cost: DATA_JET_FLAT_COST },
    }
}

#[rustfmt::skip]
pub fn evaluate_u64_checked_mul_jet(a: u64, b: u64) -> U64JetResult {
    match a.checked_mul(b) {
        Some(value) => U64JetResult { value, accepted: true, cost: DATA_JET_FLAT_COST },
        None => U64JetResult { value: 0, accepted: false, cost: DATA_JET_FLAT_COST },
    }
}

#[rustfmt::skip]
pub fn evaluate_u64_cmp_jet(a: u64, b: u64) -> OrderingJetResult {
    OrderingJetResult { ordering: a.cmp(&b), cost: DATA_JET_FLAT_COST }
}

#[rustfmt::skip]
pub fn evaluate_u128_checked_add_jet(a: Uint128, b: Uint128) -> U128JetResult {
    match a.to_native().checked_add(b.to_native()).map(Uint128::from_native) {
        Some(value) => U128JetResult { value, accepted: true, cost: DATA_JET_FLAT_COST },
        None => U128JetResult { value: Uint128 { lo: 0, hi: 0 }, accepted: false, cost: DATA_JET_FLAT_COST },
    }
}

#[rustfmt::skip]
pub fn evaluate_u128_checked_sub_jet(a: Uint128, b: Uint128) -> U128JetResult {
    match a.to_native().checked_sub(b.to_native()).map(Uint128::from_native) {
        Some(value) => U128JetResult { value, accepted: true, cost: DATA_JET_FLAT_COST },
        None => U128JetResult { value: Uint128 { lo: 0, hi: 0 }, accepted: false, cost: DATA_JET_FLAT_COST },
    }
}

#[rustfmt::skip]
pub fn evaluate_u128_cmp_jet(a: Uint128, b: Uint128) -> OrderingJetResult {
    OrderingJetResult { ordering: (a.hi, a.lo).cmp(&(b.hi, b.lo)), cost: DATA_JET_FLAT_COST }
}

#[rustfmt::skip]
pub fn evaluate_bytes_eq_jet(a: &[u8], b: &[u8]) -> BoolJetResult {
    BoolJetResult { value: a == b, cost: bytes_jet_cost(u64::try_from(a.len().max(b.len())).unwrap_or(u64::MAX)) }
}

#[rustfmt::skip]
pub fn evaluate_bytes_cmp_jet(a: &[u8], b: &[u8]) -> OrderingJetResult {
    OrderingJetResult { ordering: a.cmp(b), cost: bytes_jet_cost(u64::try_from(a.len().max(b.len())).unwrap_or(u64::MAX)) }
}

#[rustfmt::skip]
pub fn evaluate_bytes_slice_jet(src: &[u8], start: u64, length: u64) -> BytesJetResult {
    let cost = bytes_jet_cost(length);
    let Some(end) = start.checked_add(length) else {
        return BytesJetResult { bytes: Vec::new(), accepted: false, cost };
    };
    if end > u64::try_from(src.len()).unwrap_or(u64::MAX) {
        return BytesJetResult { bytes: Vec::new(), accepted: false, cost };
    }
    BytesJetResult { bytes: src[start as usize..end as usize].to_vec(), accepted: true, cost }
}

#[rustfmt::skip]
fn bytes_jet_cost(length: u64) -> u64 {
    DATA_JET_FLAT_COST + length / BYTES_JET_CHUNK_LEN + u64::from(!length.is_multiple_of(BYTES_JET_CHUNK_LEN))
}

#[rustfmt::skip]
impl Mldsa87VerifyJetResult {
    fn into_eval_result(self) -> EvalResult { EvalResult { accepted: self.verified, cost: self.cost } }
}

#[rustfmt::skip]
impl Program {
    pub fn evaluate(&self, opts: EvalOptions<'_>) -> Result<EvalResult, EvalError> {
        if !self.decoded { return Err(EvalError::new(ErrorCode::Decode)); }
        if self.has_jet { return self.evaluate_jet(opts); }
        if self.eval_steps == 0 { return Err(EvalError::new(ErrorCode::Decode)); }
        check_memory_bounds(&self.frame_bit_widths)?;
        evaluate_steps(self.eval_steps)
    }

    fn evaluate_jet(&self, opts: EvalOptions<'_>) -> Result<EvalResult, EvalError> {
        let jet = decoded_jet(self.jet_key)?;
        check_memory_bounds(&self.frame_bit_widths)?;
        let evaluator = opts.jet_evaluator.ok_or_else(|| EvalError::new(ErrorCode::JetDisallowed))?;
        metered_jet_result(evaluator(jet).map_err(|err| EvalError::new(err.code))?)
    }
}

#[rustfmt::skip]
fn evaluate_steps(steps: u64) -> Result<EvalResult, EvalError> {
    let max_steps = MAX_EXEC_COST.checked_div(STEP_COST).unwrap_or(u64::MAX);
    if steps > max_steps { return Err(EvalError::with_result(ErrorCode::BudgetExceeded, EvalResult { accepted: true, cost: MAX_EXEC_COST })); }
    Ok(EvalResult { accepted: true, cost: steps * STEP_COST })
}

#[rustfmt::skip]
fn decoded_jet(key: Option<JetKey>) -> Result<Jet, EvalError> {
    let (id, sub_op) = key.ok_or_else(|| EvalError::new(ErrorCode::Decode))?;
    lookup_jet(id, sub_op).ok_or_else(|| EvalError::new(ErrorCode::Decode))
}

#[rustfmt::skip]
fn metered_jet_result(mut result: EvalResult) -> Result<EvalResult, EvalError> {
    if result.cost > MAX_EXEC_COST {
        result.cost = MAX_EXEC_COST;
        return Err(EvalError::with_result(ErrorCode::BudgetExceeded, result));
    }
    if result.accepted { Ok(result) } else { Err(EvalError::with_result(ErrorCode::Rejected, result)) }
}

#[rustfmt::skip]
pub fn cost_model_hash() -> [u8; 32] {
    Sha3_256::digest(cost_model_bytes()).into()
}

#[rustfmt::skip]
pub fn jets_registry_hash() -> [u8; 32] {
    static HASH: OnceLock<[u8; 32]> = OnceLock::new();
    *HASH.get_or_init(|| Sha3_256::digest(jets_registry_bytes(JET_ROWS)).into())
}

#[rustfmt::skip]
pub fn rubin_jet_cmr(identity_hash: [u8; 32], jet_weight: u64) -> [u8; 32] {
    let mut state = [0x9532ee28, 0xcdca69de, 0xc8a0a218, 0xb79be362, 0xf740ceaf, 0x647f15b3, 0x8aed9168, 0x163f921b];
    let mut block = [0u8; 64];
    block[24..32].copy_from_slice(&jet_weight.to_be_bytes());
    block[32..64].copy_from_slice(&identity_hash);
    let block = GenericArray::clone_from_slice(&block);
    compress256(&mut state, core::slice::from_ref(&block));
    let words = state.map(u32::to_be_bytes);
    [words[0][0], words[0][1], words[0][2], words[0][3], words[1][0], words[1][1], words[1][2], words[1][3], words[2][0], words[2][1], words[2][2], words[2][3], words[3][0], words[3][1], words[3][2], words[3][3], words[4][0], words[4][1], words[4][2], words[4][3], words[5][0], words[5][1], words[5][2], words[5][3], words[6][0], words[6][1], words[6][2], words[6][3], words[7][0], words[7][1], words[7][2], words[7][3]]
}

#[rustfmt::skip]
fn decode_program(program: &[u8]) -> Result<Program, Error> {
    match program {
        [0x24] => program_entry("c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7", None, WitnessKind::None, 1),
        [0xc1, 0x22, 0x0f, 0x01, 0x00] => program_entry("afeae8c18903b9e0aae2c125f31f7b8e09de916e461f221936b633d587c1b434", None, WitnessKind::None, 4),
        [0x89, 0x00] => program_entry("d296a48e538af38908242ab30244036fdb66e9056d5f812a5b328fae2b6a2726", None, WitnessKind::None, 2),
        [0xc1, 0xd2, 0x10, 0x14] => program_entry("d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83", None, WitnessKind::Bool, 4),
        [0x60] => lookup_jet(0x0001, 0x00).map(jet_entry).ok_or(Error { code: ErrorCode::Decode }),
        [0x70] => lookup_jet(0x0002, 0x00).map(jet_entry).ok_or(Error { code: ErrorCode::Decode }),
        [0x7c, 0x06, 0x80] => Err(Error { code: ErrorCode::JetDisallowed }),
        _ => Err(Error { code: ErrorCode::Decode }),
    }
}

#[rustfmt::skip]
fn program_entry(cmr: &str, jet: Option<Jet>, witness_kind: WitnessKind, eval_steps: u64) -> Result<Program, Error> {
    let frames = if witness_kind == WitnessKind::Bool { BOOL_FRAMES } else { UNIT_FRAMES };
    let needs_witness = witness_kind == WitnessKind::Bool;
    let jet_key = jet.map(|j| (j.id, j.sub_op));
    Ok(Program { cmr: hex32(cmr)?, jet, needs_witness, max_witness_len: usize::from(needs_witness), witness_kind, eval_steps, decoded: false, has_jet: jet_key.is_some(), jet_key, frame_bit_widths: frames.to_vec() })
}

#[rustfmt::skip]
fn jet_entry(jet: Jet) -> Program {
    let frames = match (jet.id, jet.sub_op) { (0x0001, 0x00) => SHA3_FRAMES, (0x0002, 0x00) => MLDSA87_FRAMES, _ => &[] };
    Program { cmr: jet.cmr, jet: Some(jet), needs_witness: false, max_witness_len: 0, witness_kind: WitnessKind::None, eval_steps: 0, decoded: false, has_jet: true, jet_key: Some((jet.id, jet.sub_op)), frame_bit_widths: frames.to_vec() }
}

#[rustfmt::skip]
fn check_memory_bounds(frame_bit_widths: &[u64]) -> Result<(), EvalError> {
    let mut live = 0u64;
    for bits in frame_bit_widths {
        let frame = frame_bytes(*bits);
        if frame > MAX_FRAME_BYTES || live > MAX_LIVE_MEMORY_BYTES - frame { return Err(EvalError::new(ErrorCode::BudgetExceeded)); }
        live += frame;
    }
    Ok(())
}

#[rustfmt::skip]
fn frame_bytes(bits: u64) -> u64 { bits / 8 + u64::from(!bits.is_multiple_of(8)) }

#[rustfmt::skip]
fn cost_model_bytes() -> Vec<u8> {
    let mut out = b"RUBIN-SIMPLICITY-COST-v1".to_vec();
    out.extend_from_slice(&COST_MODEL_SEMANTICS_VERSION.to_le_bytes());
    for value in [STEP_COST, INTRINSIC_READ_COST, INTRINSIC_MISS_COST, DESCRIPTOR_HASH_BASE_COST, DESCRIPTOR_HASH_BYTE_COST, MAX_FRAME_BYTES, MAX_LIVE_MEMORY_BYTES] { out.extend_from_slice(&value.to_le_bytes()); }
    out.push(cost_model_row_count_byte(COST_MODEL_ROWS.len()));
    for row in COST_MODEL_ROWS {
        out.extend_from_slice(&row.jet.0.to_le_bytes());
        out.extend_from_slice(&[row.jet.1, row.formula as u8]);
        out.extend_from_slice(&row.param.to_le_bytes());
    }
    out
}

#[rustfmt::skip]
fn jets_registry_bytes(rows: &[JetRow]) -> Vec<u8> {
    validate_jet_registry_rows(rows).expect("valid checked-in Rubin jet registry rows");
    let mut out = b"RUBIN-SIMPLICITY-JETS-v1".to_vec();
    out.extend_from_slice(&JETS_REGISTRY_SEMANTICS_VERSION.to_le_bytes());
    append_one_byte_compact_size(&mut out, rows.len());
    for row in rows {
        out.extend_from_slice(&row.id.to_le_bytes());
        out.push(row.sub_op);
        append_one_byte_compact_size(&mut out, row.name.len());
        out.extend_from_slice(row.name.as_bytes());
        append_one_byte_compact_size(&mut out, row.signature.len());
        out.extend_from_slice(row.signature.as_bytes());
    }
    out
}

#[rustfmt::skip]
fn append_one_byte_compact_size(out: &mut Vec<u8>, value: usize) {
    assert!(value < 253, "jet registry CompactSize value exceeds one-byte encoding");
    out.push(value as u8);
}

#[rustfmt::skip]
fn validate_jet_registry_rows(rows: &[JetRow]) -> Result<(), &'static str> {
    let mut prev = None;
    for row in rows {
        let key = (row.id, row.sub_op);
        if prev.is_some_and(|prev| prev >= key) {
            return Err("jet registry rows not strictly sorted");
        }
        prev = Some(key);
    }
    Ok(())
}

#[rustfmt::skip]
fn cost_model_row_count_byte(rows: usize) -> u8 {
    assert!(rows < 253, "cost model row count exceeds one-byte CompactSize encoding");
    rows as u8
}

#[rustfmt::skip]
fn witness_allowed(kind: WitnessKind, version: u32, witness: &[u8]) -> bool {
    matches!((kind, version, witness), (WitnessKind::None, SEMANTICS_VERSION, []) | (WitnessKind::Bool, SEMANTICS_VERSION, [0x00] | [0x80]))
}

#[rustfmt::skip]
const JET_ROWS: &[JetRow] = &[
    JetRow { id: 0x0001, sub_op: 0x00, name: "sha3_256",         selector_bit_len: 2,  selector_padded: &[0x00],             cmr: "3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637", signature: "bytes -> bytes32" },
    JetRow { id: 0x0002, sub_op: 0x00, name: "mldsa87_verify",   selector_bit_len: 4,  selector_padded: &[0x80],             cmr: "f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941", signature: "(pubkey:bytes, sig:bytes, digest32:bytes32) -> bool" },
    JetRow { id: 0x0010, sub_op: 0x00, name: "u64_checked_add",  selector_bit_len: 12, selector_padded: &[0xe0, 0x00],       cmr: "4911cf2b5d37ccc5407c0d4e0686f0c6871c0b18c33ebc2dd28ec905cbec90ee", signature: "(u64, u64) -> Either<unit, u64>" },
    JetRow { id: 0x0010, sub_op: 0x01, name: "u64_checked_sub",  selector_bit_len: 14, selector_padded: &[0xe0, 0x10],       cmr: "9c2b594d0673d2f416e0bb216f15d35a55a75c2237d030493ec3ae72652f2146", signature: "(u64, u64) -> Either<unit, u64>" },
    JetRow { id: 0x0010, sub_op: 0x02, name: "u64_checked_mul",  selector_bit_len: 14, selector_padded: &[0xe0, 0x14],       cmr: "cf668e8e6a8bd1e9bcceebef182e063d1facd1665664170b6ae163456e739fa7", signature: "(u64, u64) -> Either<unit, u64>" },
    JetRow { id: 0x0010, sub_op: 0x03, name: "u64_cmp",          selector_bit_len: 17, selector_padded: &[0xe0, 0x18, 0x00], cmr: "50a228b34771cac098612f13ccf74949a8a0d8856b29440502fe8b45dd699c07", signature: "(u64, u64) -> ordering" },
    JetRow { id: 0x0011, sub_op: 0x00, name: "u128_checked_add", selector_bit_len: 12, selector_padded: &[0xe0, 0x20],       cmr: "9d4674805162aca15086e994aa03fb6d2093665316449f9cc97e5288daf14dd9", signature: "(u128, u128) -> Either<unit, u128>" },
    JetRow { id: 0x0011, sub_op: 0x01, name: "u128_checked_sub", selector_bit_len: 14, selector_padded: &[0xe0, 0x30],       cmr: "0d8bc8c7815edb3c220fd212f4c7b6986f50e8a427d6200b74f83a85c1792f75", signature: "(u128, u128) -> Either<unit, u128>" },
    JetRow { id: 0x0011, sub_op: 0x03, name: "u128_cmp",         selector_bit_len: 17, selector_padded: &[0xe0, 0x38, 0x00], cmr: "c90a66af21fc7ced71a9141082a47dbb0db878c25f432af25f382ccb055f4add", signature: "(u128, u128) -> ordering" },
    JetRow { id: 0x0020, sub_op: 0x00, name: "bytes_eq",         selector_bit_len: 13, selector_padded: &[0xe2, 0x00],       cmr: "33f82e38417283760f1d9deba367aeaa0feb4c703b69aa37dc8c2aefe7c32d4a", signature: "(bytes, bytes) -> bool" },
    JetRow { id: 0x0020, sub_op: 0x01, name: "bytes_cmp",        selector_bit_len: 15, selector_padded: &[0xe2, 0x08],       cmr: "bd237f53ad86be9b3c8bd3dcb2a36642782c07885d5afc44903b5dc6d017960a", signature: "(bytes, bytes) -> ordering" },
    JetRow { id: 0x0021, sub_op: 0x00, name: "bytes_slice",      selector_bit_len: 13, selector_padded: &[0xe2, 0x10],       cmr: "9c28e72f9da964de2c90d92c5c772211537ed2e07d20f6790c988284a87c0ce2", signature: "(src:bytes, start:u64, len:u64) -> Either<unit, bytes>" },
];

const UNIT_FRAMES: &[u64] = &[0, 0];
const BOOL_FRAMES: &[u64] = &[1, 1];
const SHA3_FRAMES: &[u64] = &[512, 256];
const MLDSA87_FRAMES: &[u64] = &[(2_592 + 4_627 + 32) * 8, 1];

#[rustfmt::skip]
const COST_MODEL_ROWS: &[CostModelRow] = &[
    CostModelRow { jet: (0x0001, 0x00), formula: CostFormula::BasePlusLen, param: SHA3_256_JET_BASE_COST },
    CostModelRow { jet: (0x0002, 0x00), formula: CostFormula::Constant, param: MLDSA87_VERIFY_JET_COST },
    CostModelRow { jet: (0x0010, 0x00), formula: CostFormula::Constant, param: 1 },
    CostModelRow { jet: (0x0010, 0x01), formula: CostFormula::Constant, param: 1 },
    CostModelRow { jet: (0x0010, 0x02), formula: CostFormula::Constant, param: 1 },
    CostModelRow { jet: (0x0010, 0x03), formula: CostFormula::Constant, param: 1 },
    CostModelRow { jet: (0x0011, 0x00), formula: CostFormula::Constant, param: 1 },
    CostModelRow { jet: (0x0011, 0x01), formula: CostFormula::Constant, param: 1 },
    CostModelRow { jet: (0x0011, 0x03), formula: CostFormula::Constant, param: 1 },
    CostModelRow { jet: (0x0020, 0x00), formula: CostFormula::OnePlusCeilLen32, param: 0 },
    CostModelRow { jet: (0x0020, 0x01), formula: CostFormula::OnePlusCeilLen32, param: 0 },
    CostModelRow { jet: (0x0021, 0x00), formula: CostFormula::OnePlusCeilLen32, param: 0 },
];

#[rustfmt::skip]
fn hex32(s: &str) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| Error { code: ErrorCode::Decode })?;
    Ok(out)
}

#[cfg(test)]
mod tests;
