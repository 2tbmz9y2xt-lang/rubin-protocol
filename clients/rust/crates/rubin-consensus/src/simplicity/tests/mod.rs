use super::*;
use serde::Deserialize;
use std::{fs, path::PathBuf};

const C1: &str = "c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7";
const C2: &str = "afeae8c18903b9e0aae2c125f31f7b8e09de916e461f221936b633d587c1b434";
const C3: &str = "d296a48e538af38908242ab30244036fdb66e9056d5f812a5b328fae2b6a2726";
const C4: &str = "d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83";
const C5: &str = "3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637";
const C6: &str = "f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941";
const ZERO_CMR: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const LONG_FAIL: &str = "2800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const DE: Option<ErrorCode> = Some(ErrorCode::Decode);
const CM: Option<ErrorCode> = Some(ErrorCode::CmrMismatch);
const JD: Option<ErrorCode> = Some(ErrorCode::JetDisallowed);

#[rustfmt::skip]
type DecodeCase = (&'static str, &'static str, u32, &'static str, Option<&'static str>, Option<ErrorCode>);

const DECODE_CASES: &[DecodeCase] = &[
    ("24", "", SEMANTICS_VERSION, "", Some(C1), None),
    ("c1220f0100", "", SEMANTICS_VERSION, "", Some(C2), None),
    ("8900", "", SEMANTICS_VERSION, "", Some(C3), None),
    ("c1d21014", "00", SEMANTICS_VERSION, C4, Some(C4), None),
    ("c1d21014", "80", SEMANTICS_VERSION, C4, Some(C4), None),
    ("60", "", SEMANTICS_VERSION, "", Some(C5), None),
    ("70", "", SEMANTICS_VERSION, "", Some(C6), None),
    ("24", "", 2, "", None, DE),
    ("25", "", SEMANTICS_VERSION, "", None, DE),
    ("24", "", SEMANTICS_VERSION, ZERO_CMR, None, CM),
    (LONG_FAIL, "", SEMANTICS_VERSION, "", None, DE),
    ("8958", "", SEMANTICS_VERSION, "", None, DE),
    ("7c0680", "", SEMANTICS_VERSION, "", None, JD),
    ("c1d21014", "", SEMANTICS_VERSION, "", None, DE),
    ("c1d21014", "01", SEMANTICS_VERSION, "", None, DE),
    ("c1d21014", "0000", SEMANTICS_VERSION, "", None, DE),
    ("2400", "", SEMANTICS_VERSION, "", None, DE),
];

#[test]
#[rustfmt::skip]
fn decode_vectors_match_go_reference() {
    for (program, witness, version, covenant, want_cmr, want_err) in DECODE_CASES {
        let got = decode(&hx(program), &hx(witness), opts(*version, covenant));
        match want_err {
            Some(code) => assert_eq!(got.unwrap_err().code, *code),
            None => {
                let got = got.unwrap();
                assert_eq!(got.cmr, hex32(want_cmr.unwrap()).unwrap());
                assert_eq!(got.jet.map(|j| (j.id, j.sub_op, j.name, j.selector_bit_len, j.selector_padded, j.cmr)), match *program { "60" => Some((0x0001, 0x00, "sha3_256", 2, &[0x00][..], hex32(C5).unwrap())), "70" => Some((0x0002, 0x00, "mldsa87_verify", 4, &[0x80][..], hex32(C6).unwrap())), _ => None });
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedCorpus {
    contract_version: u32,
    fixture_kind: String,
    description: String,
    cases: Vec<SharedCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedCase {
    id: String,
    program_hex: String,
    witness_hex: String,
    semantics_version: u32,
    #[serde(default)]
    covenant_cmr_hex: String,
    #[serde(default)]
    expected_cmr_hex: String,
    #[serde(default)]
    expected_error: String,
}

#[test]
fn shared_encoding_corpus_matches_go_reference() {
    let raw = fs::read_to_string(corpus_path()).expect("read shared corpus");
    let corpus: SharedCorpus = serde_json::from_str(&raw).expect("parse shared corpus");
    assert_eq!(corpus.contract_version, 1);
    assert_eq!(corpus.fixture_kind, "simplicity_program_encoding_cmr_v1");
    assert!(!corpus.description.is_empty());
    assert!(!corpus.cases.is_empty());
    for case in corpus.cases {
        let got = decode(
            &hx(&case.program_hex),
            &hx(&case.witness_hex),
            opts(case.semantics_version, &case.covenant_cmr_hex),
        );
        if !case.expected_error.is_empty() {
            let want = error_code(&case.expected_error).unwrap_or_else(|| {
                panic!(
                    "{}: unknown expected error {}",
                    case.id, case.expected_error
                )
            });
            match got {
                Ok(decoded) => panic!(
                    "{}: expected error {}, decoded cmr={}",
                    case.id,
                    case.expected_error,
                    hex::encode(decoded.cmr)
                ),
                Err(err) => assert_eq!(err.code, want, "{}", case.id),
            }
            continue;
        }
        let decoded = match got {
            Ok(decoded) => decoded,
            Err(err) => panic!(
                "{}: expected cmr {}, got error {}",
                case.id,
                case.expected_cmr_hex,
                err.code.as_str()
            ),
        };
        let want_cmr = hex32(&case.expected_cmr_hex).unwrap_or_else(|_| {
            panic!(
                "{}: invalid expected cmr {}",
                case.id, case.expected_cmr_hex
            )
        });
        assert_eq!(decoded.cmr, want_cmr, "{}", case.id);
    }
}

#[test]
fn program_size_boundary_matches_go_reference() {
    let mut at_cap = vec![0; MAX_PROGRAM_BYTES];
    at_cap[0] = 0x24;
    assert_eq!(decode_err(&at_cap, &[]), ErrorCode::Decode);
    let mut too_large = vec![0; MAX_PROGRAM_BYTES + 1];
    too_large[0] = 0x24;
    assert_eq!(decode_err(&too_large, &[]), ErrorCode::ProgramTooLarge);
    let oversized_witness = vec![0x01; MAX_PROGRAM_BYTES * 4];
    assert_eq!(decode_err(&hx("24"), &oversized_witness), ErrorCode::Decode);
}

#[test]
#[rustfmt::skip]
fn jet_rows_and_hashes_match_go_reference() {
    assert_eq!(JET_ROWS.len(), 12);
    for row in JET_ROWS {
        assert_eq!(lookup_jet(row.id, row.sub_op).unwrap(), Jet { id: row.id, sub_op: row.sub_op, name: row.name, selector_bit_len: row.selector_bit_len, selector_padded: row.selector_padded, cmr: hex32(row.cmr).unwrap() });
    }
    assert!(lookup_jet(0x0011, 0x02).is_none());
    assert_eq!(
        PROGRAM_ENCODING_HASH,
        hex32("27e5ad521efdf9d185c1c92a3a1a4aacc9276c2a5b1b8518ce25c8c973a38adc").unwrap()
    );
}

#[test]
fn rubin_jet_cmr_examples_match_go_reference() {
    assert_eq!(
        rubin_jet_cmr([0; 32], 1),
        hex32("f2a8d5366d7ca4a4960440c95e3c465ea3df2a5a14c0d58198c65d8aa1e796de").unwrap()
    );
    assert_eq!(
        rubin_jet_cmr([0x11; 32], 4_294_967_296),
        hex32("2e4a23492db398e98317272348128f39da97983f5cbab825d5389c2c8b908e11").unwrap()
    );
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn decode_err(program: &[u8], witness: &[u8]) -> ErrorCode {
    decode(program, witness, opts(SEMANTICS_VERSION, ""))
        .unwrap_err()
        .code
}

#[rustfmt::skip]
fn opts(version: u32, covenant: &str) -> DecodeOptions { DecodeOptions { semantics_version: version, covenant_program_cmr: optional_cmr(covenant) } }

fn optional_cmr(s: &str) -> Option<[u8; 32]> {
    (!s.is_empty()).then(|| hex32(s).unwrap())
}

fn corpus_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(
        "../../../../conformance/fixtures/protocol/simplicity_program_encoding_corpus_v1.json",
    );
    path
}

fn error_code(s: &str) -> Option<ErrorCode> {
    [
        ErrorCode::Decode,
        ErrorCode::ProgramTooLarge,
        ErrorCode::CmrMismatch,
        ErrorCode::JetDisallowed,
    ]
    .into_iter()
    .find(|code| code.as_str() == s)
}
