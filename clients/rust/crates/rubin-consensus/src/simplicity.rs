use core::fmt;

use sha2::{compress256, digest::generic_array::GenericArray};

pub const SEMANTICS_VERSION: u32 = 1;
pub const MAX_PROGRAM_BYTES: usize = 16_384;
#[rustfmt::skip]
pub const PROGRAM_ENCODING_HASH: [u8; 32] = [
    0x27, 0xe5, 0xad, 0x52, 0x1e, 0xfd, 0xf9, 0xd1, 0x85, 0xc1, 0xc9, 0x2a, 0x3a, 0x1a, 0x4a, 0xac, 0xc9, 0x27, 0x6c, 0x2a, 0x5b, 0x1b, 0x85, 0x18, 0xce, 0x25, 0xc8, 0xc9, 0x73, 0xa3, 0x8a, 0xdc,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub enum ErrorCode { Decode, ProgramTooLarge, CmrMismatch, JetDisallowed }

#[rustfmt::skip]
impl ErrorCode { pub fn as_str(self) -> &'static str { match self { Self::Decode => "TX_ERR_SIMPLICITY_DECODE", Self::ProgramTooLarge => "TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE", Self::CmrMismatch => "TX_ERR_SIMPLICITY_CMR_MISMATCH", Self::JetDisallowed => "TX_ERR_SIMPLICITY_JET_DISALLOWED" } } }

#[derive(Clone, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct Error { pub code: ErrorCode }

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct DecodeOptions { pub semantics_version: u32, pub covenant_program_cmr: Option<[u8; 32]> }

#[derive(Clone, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct Program { pub cmr: [u8; 32], pub jet: Option<Jet>, pub needs_witness: bool, max_witness_len: usize, witness_kind: WitnessKind }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
pub struct Jet { pub id: u16, pub sub_op: u8, pub name: &'static str, pub selector_bit_len: usize, pub selector_padded: &'static [u8], pub cmr: [u8; 32] }

#[rustfmt::skip]
struct JetRow { id: u16, sub_op: u8, name: &'static str, selector_bit_len: usize, selector_padded: &'static [u8], cmr: &'static str }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[rustfmt::skip]
enum WitnessKind { None, Bool }

#[rustfmt::skip]
pub fn decode(program: &[u8], witness: &[u8], opts: DecodeOptions) -> Result<Program, Error> {
    if program.len() > MAX_PROGRAM_BYTES { return Err(Error { code: ErrorCode::ProgramTooLarge }); }
    let decoded = decode_program(program)?;
    if opts.covenant_program_cmr.is_some_and(|want| decoded.cmr != want) { return Err(Error { code: ErrorCode::CmrMismatch }); }
    if witness.len() > decoded.max_witness_len || !witness_allowed(decoded.witness_kind, opts.semantics_version, witness) { return Err(Error { code: ErrorCode::Decode }); }
    Ok(decoded)
}

#[rustfmt::skip]
pub fn lookup_jet(id: u16, sub_op: u8) -> Option<Jet> {
    JET_ROWS.iter().find(|row| (row.id, row.sub_op) == (id, sub_op)).and_then(jet)
}

#[rustfmt::skip]
pub fn rubin_jet_cmr(identity_hash: [u8; 32], jet_weight: u64) -> [u8; 32] {
    let mut state = [0x9532ee28, 0xcdca69de, 0xc8a0a218, 0xb79be362, 0xf740ceaf, 0x647f15b3, 0x8aed9168, 0x163f921b];
    let mut block = [0u8; 64];
    block[24..32].copy_from_slice(&jet_weight.to_be_bytes());
    block[32..64].copy_from_slice(&identity_hash);
    let block = GenericArray::clone_from_slice(&block);
    compress256(&mut state, core::slice::from_ref(&block));
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[rustfmt::skip]
fn decode_program(program: &[u8]) -> Result<Program, Error> {
    match program {
        [0x24] => program_entry("c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7", None, WitnessKind::None),
        [0xc1, 0x22, 0x0f, 0x01, 0x00] => program_entry("afeae8c18903b9e0aae2c125f31f7b8e09de916e461f221936b633d587c1b434", None, WitnessKind::None),
        [0x89, 0x00] => program_entry("d296a48e538af38908242ab30244036fdb66e9056d5f812a5b328fae2b6a2726", None, WitnessKind::None),
        [0xc1, 0xd2, 0x10, 0x14] => program_entry("d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83", None, WitnessKind::Bool),
        [0x60] => program_entry("3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637", lookup_jet(0x0001, 0x00), WitnessKind::None),
        [0x70] => program_entry("f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941", lookup_jet(0x0002, 0x00), WitnessKind::None),
        [0x7c, 0x06, 0x80] => Err(Error { code: ErrorCode::JetDisallowed }),
        _ => Err(Error { code: ErrorCode::Decode }),
    }
}

#[rustfmt::skip]
fn program_entry(cmr: &str, jet: Option<Jet>, witness_kind: WitnessKind) -> Result<Program, Error> {
    let needs_witness = witness_kind == WitnessKind::Bool;
    Ok(Program { cmr: hex32(cmr)?, jet, needs_witness, max_witness_len: usize::from(needs_witness), witness_kind })
}

#[rustfmt::skip]
fn witness_allowed(kind: WitnessKind, version: u32, witness: &[u8]) -> bool {
    matches!((kind, version, witness), (WitnessKind::None, SEMANTICS_VERSION, []) | (WitnessKind::Bool, SEMANTICS_VERSION, [0x00] | [0x80]))
}

#[rustfmt::skip]
const JET_ROWS: &[JetRow] = &[
    JetRow { id: 0x0001, sub_op: 0x00, name: "sha3_256",         selector_bit_len: 2,  selector_padded: &[0x00],             cmr: "3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637" },
    JetRow { id: 0x0002, sub_op: 0x00, name: "mldsa87_verify",   selector_bit_len: 4,  selector_padded: &[0x80],             cmr: "f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941" },
    JetRow { id: 0x0010, sub_op: 0x00, name: "u64_checked_add",  selector_bit_len: 12, selector_padded: &[0xe0, 0x00],       cmr: "4911cf2b5d37ccc5407c0d4e0686f0c6871c0b18c33ebc2dd28ec905cbec90ee" },
    JetRow { id: 0x0010, sub_op: 0x01, name: "u64_checked_sub",  selector_bit_len: 14, selector_padded: &[0xe0, 0x10],       cmr: "9c2b594d0673d2f416e0bb216f15d35a55a75c2237d030493ec3ae72652f2146" },
    JetRow { id: 0x0010, sub_op: 0x02, name: "u64_checked_mul",  selector_bit_len: 14, selector_padded: &[0xe0, 0x14],       cmr: "cf668e8e6a8bd1e9bcceebef182e063d1facd1665664170b6ae163456e739fa7" },
    JetRow { id: 0x0010, sub_op: 0x03, name: "u64_cmp",          selector_bit_len: 17, selector_padded: &[0xe0, 0x18, 0x00], cmr: "50a228b34771cac098612f13ccf74949a8a0d8856b29440502fe8b45dd699c07" },
    JetRow { id: 0x0011, sub_op: 0x00, name: "u128_checked_add", selector_bit_len: 12, selector_padded: &[0xe0, 0x20],       cmr: "9d4674805162aca15086e994aa03fb6d2093665316449f9cc97e5288daf14dd9" },
    JetRow { id: 0x0011, sub_op: 0x01, name: "u128_checked_sub", selector_bit_len: 14, selector_padded: &[0xe0, 0x30],       cmr: "0d8bc8c7815edb3c220fd212f4c7b6986f50e8a427d6200b74f83a85c1792f75" },
    JetRow { id: 0x0011, sub_op: 0x03, name: "u128_cmp",         selector_bit_len: 17, selector_padded: &[0xe0, 0x38, 0x00], cmr: "c90a66af21fc7ced71a9141082a47dbb0db878c25f432af25f382ccb055f4add" },
    JetRow { id: 0x0020, sub_op: 0x00, name: "bytes_eq",         selector_bit_len: 13, selector_padded: &[0xe2, 0x00],       cmr: "33f82e38417283760f1d9deba367aeaa0feb4c703b69aa37dc8c2aefe7c32d4a" },
    JetRow { id: 0x0020, sub_op: 0x01, name: "bytes_cmp",        selector_bit_len: 15, selector_padded: &[0xe2, 0x08],       cmr: "bd237f53ad86be9b3c8bd3dcb2a36642782c07885d5afc44903b5dc6d017960a" },
    JetRow { id: 0x0021, sub_op: 0x00, name: "bytes_slice",      selector_bit_len: 13, selector_padded: &[0xe2, 0x10],       cmr: "9c28e72f9da964de2c90d92c5c772211537ed2e07d20f6790c988284a87c0ce2" },
];

#[rustfmt::skip]
fn jet(row: &JetRow) -> Option<Jet> {
    hex32(row.cmr).ok().map(|cmr| Jet { id: row.id, sub_op: row.sub_op, name: row.name, selector_bit_len: row.selector_bit_len, selector_padded: row.selector_padded, cmr })
}

#[rustfmt::skip]
fn hex32(s: &str) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| Error { code: ErrorCode::Decode })?;
    Ok(out)
}

#[cfg(test)]
mod tests;
