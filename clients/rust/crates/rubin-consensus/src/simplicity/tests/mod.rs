use super::*;
use serde::{de::Error as _, Deserialize};
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedExecCorpus {
    contract_version: u32,
    fixture_kind: String,
    description: String,
    cases: Vec<SharedExecCase>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedExecCase {
    id: String,
    #[serde(default)]
    program_hex: String,
    #[serde(default)]
    witness_hex: String,
    #[serde(default)]
    eval_steps: u64,
    #[serde(default)]
    frame_bit_widths: Vec<u64>,
    #[serde(default)]
    jet_accepted: bool,
    #[serde(default)]
    jet_cost: u64,
    expected_accepted: bool,
    #[serde(default)]
    expected_error: String,
    expected_final_counter: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedCryptoJetsCorpus {
    contract_version: u32,
    fixture_kind: String,
    description: String,
    cases: Vec<SharedCryptoJetCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedCryptoJetCase {
    id: String,
    jet: String,
    #[serde(default)]
    message_hex: String,
    #[serde(default)]
    expected_digest_hex: String,
    #[serde(default)]
    digest_hex: String,
    #[serde(default)]
    pubkey_len: usize,
    #[serde(default)]
    signature_len: usize,
    #[serde(default)]
    verifier_result: bool,
    #[serde(default)]
    expected_verified: bool,
    expected_cost: u64,
    #[serde(default)]
    expect_verifier_called: bool,
    #[serde(default)]
    expected_error: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedDataJetsCorpus {
    contract_version: u32,
    fixture_kind: String,
    description: String,
    cases: Vec<SharedDataJetCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedJetsRegistryCorpus {
    contract_version: u32,
    fixture_kind: String,
    description: String,
    expected_registry_hash_hex: String,
    cases: Vec<SharedJetsRegistryCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedJetsRegistryCase {
    id: String,
    jet_id: u16,
    sub_op: u8,
    #[serde(default)]
    name: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    program_hex: String,
    expected_present: bool,
    #[serde(default)]
    expected_error: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedDataJetCase {
    id: String,
    jet: String,
    a_u64: Option<u64>,
    b_u64: Option<u64>,
    a_u128_hi: Option<u64>,
    a_u128_lo: Option<u64>,
    b_u128_hi: Option<u64>,
    b_u128_lo: Option<u64>,
    bytes_a_hex: Option<String>,
    bytes_b_hex: Option<String>,
    source_hex: Option<String>,
    start: Option<u64>,
    length: Option<u64>,
    expected_accepted: Option<bool>,
    expected_u64: Option<u64>,
    expected_u128_hi: Option<u64>,
    expected_u128_lo: Option<u64>,
    expected_ordering: Option<i8>,
    expected_bool: Option<bool>,
    expected_bytes_hex: Option<String>,
    expected_cost: Option<u64>,
    #[serde(skip, rename = "__rubin_internal_field_count")]
    field_count: usize,
}

#[test]
fn shared_exec_corpus_requires_outcome_fields() {
    for (name, raw, needle) in [
        (
            "missing accepted",
            r#"{"contract_version":1,"fixture_kind":"simplicity_exec_corpus_v1","description":"x","cases":[{"id":"VEC-SE-MISSING-ACCEPTED","expected_final_counter":0}]}"#,
            "missing field `expected_accepted`",
        ),
        (
            "missing final counter",
            r#"{"contract_version":1,"fixture_kind":"simplicity_exec_corpus_v1","description":"x","cases":[{"id":"VEC-SE-MISSING-COUNTER","expected_accepted":false}]}"#,
            "missing field `expected_final_counter`",
        ),
    ] {
        let err = match serde_json::from_str::<SharedExecCorpus>(raw) {
            Ok(_) => panic!("{name}: malformed corpus parsed successfully"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains(needle),
            "{name}: error={err} want {needle}"
        );
    }
}

#[test]
fn shared_exec_corpus_matches_go_reference() {
    let raw = fs::read_to_string(exec_corpus_path()).expect("read shared exec corpus");
    let corpus: SharedExecCorpus = serde_json::from_str(&raw).expect("parse shared exec corpus");
    assert_eq!(corpus.contract_version, 1);
    assert_eq!(corpus.fixture_kind, "simplicity_exec_corpus_v1");
    assert!(!corpus.description.is_empty());
    assert!(!corpus.cases.is_empty());
    for case in corpus.cases {
        match evaluate_shared_exec_case(&case) {
            Ok(got) => {
                assert!(case.expected_error.is_empty(), "{}", case.id);
                assert_eq!(got.accepted, case.expected_accepted, "{}", case.id);
                assert_eq!(got.cost, case.expected_final_counter, "{}", case.id);
            }
            Err(err) => {
                let want = error_code(&case.expected_error).unwrap_or_else(|| {
                    panic!(
                        "{}: unknown expected error {}",
                        case.id, case.expected_error
                    )
                });
                assert_eq!(err.code, want, "{}", case.id);
                assert_eq!(err.result.accepted, case.expected_accepted, "{}", case.id);
                assert_eq!(err.result.cost, case.expected_final_counter, "{}", case.id);
            }
        }
    }
}

#[test]
fn shared_crypto_jets_corpus_matches_go_reference() {
    let raw =
        fs::read_to_string(crypto_jets_corpus_path()).expect("read shared crypto jets corpus");
    let corpus: SharedCryptoJetsCorpus =
        serde_json::from_str(&raw).expect("parse shared crypto jets corpus");
    assert_eq!(corpus.contract_version, 1);
    assert_eq!(corpus.fixture_kind, "simplicity_crypto_jets_corpus_v1");
    assert!(!corpus.description.is_empty() && !corpus.cases.is_empty());
    for case in corpus.cases {
        match case.jet.as_str() {
            "sha3_256" => {
                let got = evaluate_sha3_256_jet(&hx(&case.message_hex));
                assert_eq!(
                    got.digest,
                    hex32(&case.expected_digest_hex)
                        .unwrap_or_else(|_| panic!("{}: bad digest", case.id)),
                    "{}",
                    case.id
                );
                assert_eq!(got.cost, case.expected_cost, "{}", case.id);
            }
            "mldsa87_verify" => {
                let digest =
                    hex32(&case.digest_hex).unwrap_or_else(|_| panic!("{}: bad digest", case.id));
                let called = std::cell::Cell::new(false);
                let verifier = |pubkey: &[u8], signature: &[u8], got_digest: [u8; 32]| {
                    called.set(true);
                    assert_eq!(pubkey.len(), case.pubkey_len, "{}", case.id);
                    assert_eq!(signature.len(), case.signature_len, "{}", case.id);
                    assert_eq!(got_digest, digest, "{}", case.id);
                    if !case.expected_error.is_empty() {
                        return Err(EvalError::new(error_code(&case.expected_error).unwrap()));
                    }
                    Ok(case.verifier_result)
                };
                let got = match evaluate_mldsa87_verify_jet(
                    &vec![0x11; case.pubkey_len],
                    &vec![0x22; case.signature_len],
                    digest,
                    Some(&verifier),
                ) {
                    Ok(got) => got,
                    Err(err) => {
                        assert_eq!(
                            err.code,
                            error_code(&case.expected_error).unwrap(),
                            "{}",
                            case.id
                        );
                        assert_eq!(err.result.cost, case.expected_cost, "{}", case.id);
                        assert_eq!(called.get(), case.expect_verifier_called, "{}", case.id);
                        continue;
                    }
                };
                assert!(case.expected_error.is_empty(), "{}", case.id);
                assert_eq!(got.verified, case.expected_verified, "{}", case.id);
                assert_eq!(got.cost, case.expected_cost, "{}", case.id);
                assert_eq!(called.get(), case.expect_verifier_called, "{}", case.id);
            }
            _ => panic!("{}: unknown jet {}", case.id, case.jet),
        }
    }
}

#[test]
fn shared_data_jets_corpus_matches_go_reference() -> Result<(), String> {
    let raw = fs::read_to_string(data_jets_corpus_path()).expect("read shared data jets corpus");
    let corpus: SharedDataJetsCorpus =
        decode_shared_data_jets_corpus(&raw).expect("parse shared data jets corpus");
    assert_eq!(corpus.contract_version, 1);
    assert_eq!(corpus.fixture_kind, "simplicity_data_jets_corpus_v1");
    assert!(!corpus.description.is_empty() && !corpus.cases.is_empty());
    for case in corpus.cases {
        case.validate_outcome_fields()
            .unwrap_or_else(|err| panic!("{err}"));
        let expected_cost = case.expected_cost.expect("validated expected_cost");
        match case.jet.as_str() {
            "u64_checked_add" | "u64_checked_sub" | "u64_checked_mul" => {
                let (a, b) = case.u64_inputs();
                let got = match case.jet.as_str() {
                    "u64_checked_add" => evaluate_u64_checked_add_jet(a, b),
                    "u64_checked_sub" => evaluate_u64_checked_sub_jet(a, b),
                    _ => evaluate_u64_checked_mul_jet(a, b),
                };
                assert_eq!(
                    got,
                    U64JetResult {
                        value: case.expected_u64.expect("validated expected_u64"),
                        accepted: case.expected_accepted.expect("validated expected_accepted"),
                        cost: expected_cost,
                    },
                    "{}",
                    case.id
                );
            }
            "u64_cmp" => assert_eq!(
                {
                    let (a, b) = case.u64_inputs();
                    evaluate_u64_cmp_jet(a, b)
                },
                ordering_jet(case.expected_ordering()?, expected_cost),
                "{}",
                case.id
            ),
            "u128_checked_add" | "u128_checked_sub" => {
                let (a128, b128) = case.u128_inputs();
                let got = match case.jet.as_str() {
                    "u128_checked_add" => evaluate_u128_checked_add_jet(a128, b128),
                    _ => evaluate_u128_checked_sub_jet(a128, b128),
                };
                assert_eq!(
                    got,
                    U128JetResult {
                        value: uint128(
                            case.expected_u128_hi.expect("validated expected_u128_hi"),
                            case.expected_u128_lo.expect("validated expected_u128_lo"),
                        ),
                        accepted: case.expected_accepted.expect("validated expected_accepted"),
                        cost: expected_cost,
                    },
                    "{}",
                    case.id
                );
            }
            "u128_cmp" => assert_eq!(
                {
                    let (a128, b128) = case.u128_inputs();
                    evaluate_u128_cmp_jet(a128, b128)
                },
                ordering_jet(case.expected_ordering()?, expected_cost),
                "{}",
                case.id
            ),
            "bytes_eq" => assert_eq!(
                {
                    let (a, b) = case.bytes_pair_inputs();
                    evaluate_bytes_eq_jet(&hx(a), &hx(b))
                },
                bool_jet(
                    case.expected_bool.expect("validated expected_bool"),
                    expected_cost
                ),
                "{}",
                case.id
            ),
            "bytes_cmp" => assert_eq!(
                {
                    let (a, b) = case.bytes_pair_inputs();
                    evaluate_bytes_cmp_jet(&hx(a), &hx(b))
                },
                ordering_jet(case.expected_ordering()?, expected_cost),
                "{}",
                case.id
            ),
            "bytes_slice" => assert_eq!(
                {
                    let (source, start, length) = case.slice_inputs();
                    evaluate_bytes_slice_jet(&hx(source), start, length)
                },
                bytes_jet(
                    &hx(case
                        .expected_bytes_hex
                        .as_deref()
                        .expect("validated expected_bytes_hex")),
                    case.expected_accepted.expect("validated expected_accepted"),
                    expected_cost
                ),
                "{}",
                case.id
            ),
            _ => panic!("{}: unknown data jet {}", case.id, case.jet),
        }
    }
    Ok(())
}

#[test]
fn shared_jets_registry_corpus_matches_go_reference() {
    let raw =
        fs::read_to_string(jets_registry_corpus_path()).expect("read shared jets registry corpus");
    let corpus: SharedJetsRegistryCorpus =
        serde_json::from_str(&raw).expect("parse shared jets registry corpus");
    assert_eq!(corpus.contract_version, 1);
    assert_eq!(corpus.fixture_kind, "simplicity_jets_registry_corpus_v1");
    assert!(!corpus.description.is_empty() && !corpus.cases.is_empty());
    assert_eq!(
        jets_registry_hash(),
        hex32(&corpus.expected_registry_hash_hex).expect("valid registry hash")
    );
    for case in corpus.cases {
        let row = JET_ROWS
            .iter()
            .find(|row| (row.id, row.sub_op) == (case.jet_id, case.sub_op));
        assert_eq!(row.is_some(), case.expected_present, "{}", case.id);
        if let Some(row) = row {
            assert_eq!(
                (row.name, row.signature),
                (case.name.as_str(), case.signature.as_str()),
                "{}",
                case.id
            );
        } else if !case.program_hex.is_empty() {
            let want = error_code(&case.expected_error).unwrap();
            assert_eq!(decode_err(&hx(&case.program_hex), &[]), want, "{}", case.id);
        }
    }
}

#[test]
#[rustfmt::skip]
fn shared_data_jets_corpus_requires_outcome_fields() {
    assert!(matches!(serde_json::from_str::<SharedDataJetsCorpus>(r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-DUP","id":"VEC-SDJ-DUP2","jet":"u64_cmp","a_u64":0,"b_u64":0,"expected_ordering":0,"expected_cost":1}]}"#), Err(err) if err.to_string().contains("duplicate field `id`")));
    assert!(matches!(decode_shared_data_jets_corpus(r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-INTERNAL-FIELD-COUNT","jet":"bytes_eq","bytes_a_hex":"","bytes_b_hex":"","expected_bool":true,"expected_cost":1,"field_count":6}]}"#), Err(err) if err.to_string().contains("unknown field `field_count`")));
    for (name, raw, needle) in [
        ("missing u64 accepted", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-ACCEPTED","jet":"u64_checked_add","a_u64":0,"b_u64":0,"expected_u64":0,"expected_cost":1}]}"#, "missing expected_accepted"),
        ("missing u64 input", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-A-U64","jet":"u64_checked_add","b_u64":3,"expected_accepted":true,"expected_u64":3,"expected_cost":1}]}"#, "missing a_u64"),
        ("missing u64 value", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-U64","jet":"u64_checked_add","a_u64":0,"b_u64":0,"expected_accepted":false,"expected_cost":1}]}"#, "missing expected_u64"),
        ("missing ordering", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-ORDERING","jet":"bytes_cmp","bytes_a_hex":"","bytes_b_hex":"","expected_cost":2}]}"#, "missing expected_ordering"),
        ("invalid ordering", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-BAD-ORDERING","jet":"u64_cmp","a_u64":0,"b_u64":0,"expected_ordering":2,"expected_cost":1}]}"#, "invalid expected_ordering 2"),
        ("missing bool", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-BOOL","jet":"bytes_eq","bytes_a_hex":"","bytes_b_hex":"","expected_cost":1}]}"#, "missing expected_bool"),
        ("missing bytes input", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-BYTES-A","jet":"bytes_eq","bytes_b_hex":"","expected_bool":true,"expected_cost":1}]}"#, "missing bytes_a_hex"),
        ("missing bytes", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-BYTES","jet":"bytes_slice","source_hex":"","start":0,"length":0,"expected_accepted":false,"expected_cost":2}]}"#, "missing expected_bytes_hex"),
        ("missing u128 input", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-A-U128-HI","jet":"u128_checked_sub","a_u128_lo":0,"b_u128_hi":0,"b_u128_lo":1,"expected_accepted":false,"expected_u128_hi":0,"expected_u128_lo":0,"expected_cost":1}]}"#, "missing a_u128_hi"),
        ("missing slice input", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-START","jet":"bytes_slice","source_hex":"616263","length":0,"expected_accepted":true,"expected_bytes_hex":"","expected_cost":1}]}"#, "missing start"),
        ("missing cost", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-COST","jet":"u64_cmp","a_u64":0,"b_u64":0,"expected_ordering":0}]}"#, "missing expected_cost"),
        ("extra known field", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-EXTRA","jet":"bytes_eq","bytes_a_hex":"","bytes_b_hex":"","expected_bool":true,"expected_cost":1,"expected_u64":0}]}"#, "unexpected field count"),
        ("extra beats invalid ordering", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-EXTRA-ORDERING","jet":"bytes_eq","bytes_a_hex":"","bytes_b_hex":"","expected_bool":true,"expected_cost":1,"expected_ordering":2}]}"#, "unexpected field count"),
        ("invalid bytes eq hex", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-BAD-BYTES-A","jet":"bytes_eq","bytes_a_hex":"zz","bytes_b_hex":"","expected_bool":false,"expected_cost":1}]}"#, "invalid bytes_a_hex"),
        ("invalid bytes cmp hex", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-BAD-BYTES-B","jet":"bytes_cmp","bytes_a_hex":"","bytes_b_hex":"0","expected_ordering":0,"expected_cost":2}]}"#, "invalid bytes_b_hex"),
        ("invalid bytes slice hex", r#"{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-BAD-SOURCE","jet":"bytes_slice","source_hex":"zz","start":0,"length":0,"expected_accepted":false,"expected_bytes_hex":"","expected_cost":2}]}"#, "invalid source_hex"),
    ] {
        let corpus = decode_shared_data_jets_corpus(raw)
            .unwrap_or_else(|err| panic!("{name}: parse malformed corpus: {err}"));
        let err = corpus.cases[0]
            .validate_outcome_fields()
            .expect_err("malformed corpus parsed successfully");
        assert!(err.contains(needle), "{name}: error={err} want {needle}");
    }
}

#[test]
fn shared_data_jets_corpus_rejects_reserved_field_count_key() {
    let raw = serde_json::json!({
        "contract_version": 1,
        "fixture_kind": "simplicity_data_jets_corpus_v1",
        "description": "x",
        "cases": [{
            "id": "VEC-SDJ-RESERVED-FIELD-COUNT",
            "jet": "bytes_eq",
            "bytes_a_hex": "",
            "bytes_b_hex": "",
            "expected_bool": true,
            "expected_cost": 1,
            "__rubin_internal_field_count": 6,
        }],
    })
    .to_string();
    let err = match decode_shared_data_jets_corpus(&raw) {
        Ok(_) => panic!("reserved bookkeeping key parsed successfully"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("unknown field `__rubin_internal_field_count`"),
        "error={err}"
    );
}

fn decode_shared_data_jets_corpus(raw: &str) -> serde_json::Result<SharedDataJetsCorpus> {
    #[derive(Deserialize)]
    struct RawCorpus {
        cases: Vec<serde_json::Map<String, serde_json::Value>>,
    }
    let raw_cases: RawCorpus = serde_json::from_str(raw)?;
    for fields in &raw_cases.cases {
        if fields.contains_key("__rubin_internal_field_count") {
            return Err(serde_json::Error::custom(
                "unknown field `__rubin_internal_field_count`",
            ));
        }
    }
    let mut corpus: SharedDataJetsCorpus = serde_json::from_str(raw)?;
    if raw_cases.cases.len() != corpus.cases.len() {
        return Err(serde_json::Error::custom(format!(
            "case count drift: raw={} decoded={}",
            raw_cases.cases.len(),
            corpus.cases.len()
        )));
    }
    for (case, fields) in corpus.cases.iter_mut().zip(raw_cases.cases) {
        case.field_count = fields.len();
    }
    Ok(corpus)
}

impl SharedDataJetCase {
    fn validate_outcome_fields(&self) -> Result<(), String> {
        if self.expected_cost.is_none() {
            return Err(self.missing_field("expected_cost"));
        }
        match self.jet.as_str() {
            "u64_checked_add" | "u64_checked_sub" | "u64_checked_mul" => {
                self.require_u64_inputs()?;
                if self.expected_accepted.is_none() {
                    return Err(self.missing_field("expected_accepted"));
                }
                if self.expected_u64.is_none() {
                    return Err(self.missing_field("expected_u64"));
                }
            }
            "u64_cmp" => {
                self.require_u64_inputs()?;
                self.require_present("expected_ordering", self.expected_ordering.is_some())?;
            }
            "u128_cmp" => {
                self.require_u128_inputs()?;
                self.require_present("expected_ordering", self.expected_ordering.is_some())?;
            }
            "bytes_cmp" => {
                self.require_bytes_pair_inputs()?;
                self.require_present("expected_ordering", self.expected_ordering.is_some())?;
            }
            "u128_checked_add" | "u128_checked_sub" => {
                self.require_u128_inputs()?;
                if self.expected_accepted.is_none() {
                    return Err(self.missing_field("expected_accepted"));
                }
                if self.expected_u128_hi.is_none() {
                    return Err(self.missing_field("expected_u128_hi"));
                }
                if self.expected_u128_lo.is_none() {
                    return Err(self.missing_field("expected_u128_lo"));
                }
            }
            "bytes_eq" => {
                self.require_bytes_pair_inputs()?;
                if self.expected_bool.is_none() {
                    return Err(self.missing_field("expected_bool"));
                }
            }
            "bytes_slice" => {
                self.require_slice_inputs()?;
                if self.expected_accepted.is_none() {
                    return Err(self.missing_field("expected_accepted"));
                }
                self.require_present("expected_bytes_hex", self.expected_bytes_hex.is_some())?;
            }
            _ => return Err(format!("{}: unknown data jet {}", self.id, self.jet)),
        }
        let want = self.expected_field_count();
        if self.field_count != want {
            return Err(format!(
                "{}: unexpected field count {} for {}, want {want}",
                self.id, self.field_count, self.jet
            ));
        }
        self.validate_formats()?;
        Ok(())
    }

    fn require_u64_inputs(&self) -> Result<(), String> {
        self.require_present("a_u64", self.a_u64.is_some())?;
        self.require_present("b_u64", self.b_u64.is_some())
    }

    fn require_u128_inputs(&self) -> Result<(), String> {
        self.require_present("a_u128_hi", self.a_u128_hi.is_some())?;
        self.require_present("a_u128_lo", self.a_u128_lo.is_some())?;
        self.require_present("b_u128_hi", self.b_u128_hi.is_some())?;
        self.require_present("b_u128_lo", self.b_u128_lo.is_some())
    }

    fn require_bytes_pair_inputs(&self) -> Result<(), String> {
        self.require_present("bytes_a_hex", self.bytes_a_hex.is_some())?;
        self.require_present("bytes_b_hex", self.bytes_b_hex.is_some())
    }

    fn require_slice_inputs(&self) -> Result<(), String> {
        self.require_present("source_hex", self.source_hex.is_some())?;
        self.require_present("start", self.start.is_some())?;
        self.require_present("length", self.length.is_some())
    }

    fn require_hex(&self, field: &str, value: Option<&str>) -> Result<(), String> {
        let value = value.ok_or_else(|| self.missing_field(field))?;
        hex::decode(value)
            .map(|_| ())
            .map_err(|err| format!("{}: invalid {field} for {}: {err}", self.id, self.jet))
    }

    fn require_present(&self, field: &str, ok: bool) -> Result<(), String> {
        ok.then_some(()).ok_or_else(|| self.missing_field(field))
    }

    #[rustfmt::skip]
    fn validate_formats(&self) -> Result<(), String> { if let Some(value) = self.expected_ordering { self.ordering_from_i8(value)?; } match self.jet.as_str() { "bytes_eq" | "bytes_cmp" => { self.require_hex("bytes_a_hex", self.bytes_a_hex.as_deref())?; self.require_hex("bytes_b_hex", self.bytes_b_hex.as_deref()) }, "bytes_slice" => { self.require_hex("source_hex", self.source_hex.as_deref())?; self.require_hex("expected_bytes_hex", self.expected_bytes_hex.as_deref()) }, _ => Ok(()) } }

    #[rustfmt::skip]
    fn expected_field_count(&self) -> usize { match self.jet.as_str() { "u64_checked_add" | "u64_checked_sub" | "u64_checked_mul" => 7, "u64_cmp" | "bytes_eq" | "bytes_cmp" => 6, "u128_checked_add" | "u128_checked_sub" => 10, "u128_cmp" | "bytes_slice" => 8, _ => unreachable!() } }

    #[rustfmt::skip]
    fn u64_inputs(&self) -> (u64, u64) {
        (self.a_u64.expect("validated a_u64"), self.b_u64.expect("validated b_u64"))
    }

    #[rustfmt::skip]
    fn u128_inputs(&self) -> (Uint128, Uint128) { (uint128(self.a_u128_hi.expect("validated a_u128_hi"), self.a_u128_lo.expect("validated a_u128_lo")), uint128(self.b_u128_hi.expect("validated b_u128_hi"), self.b_u128_lo.expect("validated b_u128_lo"))) }

    #[rustfmt::skip]
    fn bytes_pair_inputs(&self) -> (&str, &str) {
        (self.bytes_a_hex.as_deref().expect("validated bytes_a_hex"), self.bytes_b_hex.as_deref().expect("validated bytes_b_hex"))
    }

    #[rustfmt::skip]
    fn slice_inputs(&self) -> (&str, u64, u64) {
        (self.source_hex.as_deref().expect("validated source_hex"), self.start.expect("validated start"), self.length.expect("validated length"))
    }

    fn missing_field(&self, field: &str) -> String {
        format!("{}: missing {field} for {}", self.id, self.jet)
    }

    #[rustfmt::skip]
    fn expected_ordering(&self) -> Result<core::cmp::Ordering, String> { self.ordering_from_i8(self.expected_ordering.ok_or_else(|| self.missing_field("expected_ordering"))?) }

    #[rustfmt::skip]
    fn ordering_from_i8(&self, value: i8) -> Result<core::cmp::Ordering, String> { match value { -1 => Ok(core::cmp::Ordering::Less), 0 => Ok(core::cmp::Ordering::Equal), 1 => Ok(core::cmp::Ordering::Greater), _ => Err(format!("{}: invalid expected_ordering {value} for {}", self.id, self.jet)) } }
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

#[test]
fn cost_model_hash_matches_go_reference() {
    let want_preimage = concat!(
        "525542494e2d53494d504c49434954592d434f53542d76310200000001000000000000000100000000000000010000000000000040000000000000000100000000000000000001000000000000001000000000000c",
        "0100000140000000000000000200000050c3000000000000100000000100000000000000100001000100000000000000100002000100000000000000100003000100000000000000110000000100000000000000110001000100000000000000110003000100000000000000200000020000000000000000200001020000000000000000210000020000000000000000",
    );
    assert_eq!(hex::encode(cost_model_bytes()), want_preimage);
    assert_eq!(
        cost_model_hash(),
        hex32("accb55570168bd7b1fedadff2135c99e32508680ff7a315cf4f33f97744aabc9").unwrap()
    );
}

#[test]
fn jets_registry_hash_matches_go_reference() {
    let want_preimage = concat!(
        "525542494e2d53494d504c49434954592d4a4554532d7631020000000c010000",
        "08736861335f323536106279746573202d3e20627974657333320200000e6d6c",
        "64736138375f76657269667933287075626b65793a62797465732c207369673a",
        "62797465732c2064696765737433323a6279746573333229202d3e20626f6f6c",
        "1000000f7536345f636865636b65645f6164641f287536342c2075363429202d",
        "3e204569746865723c756e69742c207536343e1000010f7536345f636865636b",
        "65645f7375621f287536342c2075363429202d3e204569746865723c756e6974",
        "2c207536343e1000020f7536345f636865636b65645f6d756c1f287536342c20",
        "75363429202d3e204569746865723c756e69742c207536343e10000307753634",
        "5f636d7016287536342c2075363429202d3e206f72646572696e671100001075",
        "3132385f636865636b65645f6164642228753132382c207531323829202d3e20",
        "4569746865723c756e69742c20753132383e11000110753132385f636865636b",
        "65645f7375622228753132382c207531323829202d3e204569746865723c756e",
        "69742c20753132383e11000308753132385f636d701828753132382c20753132",
        "3829202d3e206f72646572696e672000000862797465735f6571162862797465",
        "732c20627974657329202d3e20626f6f6c2000010962797465735f636d701a28",
        "62797465732c20627974657329202d3e206f72646572696e672100000b627974",
        "65735f736c69636536287372633a62797465732c2073746172743a7536342c20",
        "6c656e3a75363429202d3e204569746865723c756e69742c2062797465733e",
    );
    assert_eq!(hex::encode(jets_registry_bytes(JET_ROWS)), want_preimage);
    assert_eq!(
        jets_registry_hash(),
        hex32("5aee78aae6b610a3eb3c05bd1487523e318418e0419de48e4fe9555b37f1c059").unwrap()
    );
}

#[test]
fn jets_registry_rows_reject_duplicates_and_order_drift() {
    let mut duplicate = JET_ROWS.to_vec();
    duplicate[1] = duplicate[0];
    assert_eq!(
        validate_jet_registry_rows(&duplicate),
        Err("jet registry rows not strictly sorted")
    );

    let mut order_drift = JET_ROWS.to_vec();
    order_drift.swap(0, 1);
    assert_eq!(
        validate_jet_registry_rows(&order_drift),
        Err("jet registry rows not strictly sorted")
    );
}

#[test]
fn cost_model_rows_match_jet_table() {
    assert_eq!(COST_MODEL_ROWS.len(), JET_ROWS.len());
    assert!(COST_MODEL_ROWS.len() < 253);
    let mut prev = (0, 0);
    for (i, row) in COST_MODEL_ROWS.iter().enumerate() {
        assert!(
            lookup_jet(row.jet.0, row.jet.1).is_some(),
            "missing jet row {i}"
        );
        assert!(i == 0 || prev < row.jet, "cost rows not sorted at {i}");
        assert!(row.formula <= CostFormula::OnePlusCeilLen32);
        assert!(row.formula != CostFormula::OnePlusCeilLen32 || row.param == 0);
        prev = row.jet;
    }
}

#[test]
#[should_panic(expected = "cost model row count exceeds one-byte CompactSize encoding")]
fn cost_model_row_count_rejects_multi_byte_compact_size() {
    let _ = cost_model_row_count_byte(253);
}

#[test]
#[rustfmt::skip]
fn sha3_256_jet_uses_native_sha3_and_charges_by_message_len() {
    for msg in [&[][..], b"abc", &[0xa5; 65][..]] {
        let got = evaluate_sha3_256_jet(msg);
        assert_eq!(got.digest, crate::hash::sha3_256(msg));
        assert_eq!(got.cost, SHA3_256_JET_BASE_COST + u64::try_from(msg.len()).unwrap());
    }
}

#[test]
#[rustfmt::skip]
fn mldsa87_verify_jet_length_mismatch_is_program_false() {
    let digest = crate::hash::sha3_256(b"");
    let called = std::cell::Cell::new(false);
    let verifier = |_: &[u8], _: &[u8], _: [u8; 32]| { called.set(true); Ok(true) };
    for (pubkey_len, sig_len) in [
        (MLDSA87_JET_PUBKEY_BYTES - 1, MLDSA87_JET_SIG_BYTES),
        (MLDSA87_JET_PUBKEY_BYTES, MLDSA87_JET_SIG_BYTES - 1),
        (MLDSA87_JET_PUBKEY_BYTES, MLDSA87_JET_SIG_BYTES + 1),
    ] {
        called.set(false);
        let got = evaluate_mldsa87_verify_jet(&vec![0; pubkey_len], &vec![0; sig_len], digest, Some(&verifier)).unwrap();
        assert!(!called.get());
        assert_eq!(got, mldsa_result(false));
    }
}

#[test]
#[rustfmt::skip]
fn mldsa87_verify_jet_calls_verifier_for_valid_lengths() {
    let pubkey = vec![0x11; MLDSA87_JET_PUBKEY_BYTES];
    let signature = vec![0x22; MLDSA87_JET_SIG_BYTES];
    let digest = [0x33; 32];
    let verifier = |got_pubkey: &[u8], got_signature: &[u8], got_digest: [u8; 32]| {
        assert_eq!(got_pubkey, pubkey);
        assert_eq!(got_signature, signature);
        assert_eq!(got_digest, digest);
        Ok(true)
    };
    let got = evaluate_mldsa87_verify_jet(&pubkey, &signature, digest, Some(&verifier)).unwrap();
    assert_eq!(got, mldsa_result(true));
}

#[test]
#[rustfmt::skip]
fn mldsa87_verify_jet_uses_native_backend_and_flat_cost() {
    let keypair = match crate::Mldsa87Keypair::generate() {
        Ok(value) => value,
        Err(err) if err.code == crate::error::ErrorCode::TxErrParse && err.msg.contains("EVP_PKEY_CTX_new_from_name") => return,
        Err(err) => panic!("unexpected ML-DSA-87 keypair failure: {err}"),
    };
    let mut digest = crate::hash::sha3_256(b"simplicity mldsa87_verify");
    let signature = keypair.sign_digest32(digest).expect("sign digest");
    let pubkey = keypair.pubkey_bytes();
    let verifier = |pk: &[u8], sig: &[u8], d: [u8; 32]| crate::verify_sig(crate::constants::SUITE_ID_ML_DSA_87, pk, sig, &d).map_err(|_| EvalError::new(ErrorCode::JetDisallowed));
    assert_eq!(evaluate_mldsa87_verify_jet(&pubkey, &signature, digest, Some(&verifier)).unwrap(), mldsa_result(true));
    digest[0] ^= 0xff;
    assert_eq!(evaluate_mldsa87_verify_jet(&pubkey, &signature, digest, Some(&verifier)).unwrap(), mldsa_result(false));
}

#[test]
#[rustfmt::skip]
fn mldsa87_verify_jet_requires_verifier_for_valid_lengths() {
    let err = evaluate_mldsa87_verify_jet(&vec![0; MLDSA87_JET_PUBKEY_BYTES], &vec![0; MLDSA87_JET_SIG_BYTES], [0; 32], None).unwrap_err();
    assert_eq!(err.code, ErrorCode::JetDisallowed);
    assert_eq!(err.result, rejected(MLDSA87_VERIFY_JET_COST));
}

#[test]
#[rustfmt::skip]
fn mldsa87_verify_jet_propagates_verifier_error_code_with_flat_cost() {
    let verifier = |_: &[u8], _: &[u8], _: [u8; 32]| Err(EvalError { code: ErrorCode::Decode, result: ok(9) });
    let err = evaluate_mldsa87_verify_jet(&vec![0; MLDSA87_JET_PUBKEY_BYTES], &vec![0; MLDSA87_JET_SIG_BYTES], [0; 32], Some(&verifier)).unwrap_err();
    assert_eq!(err.code, ErrorCode::Decode);
    assert_eq!(err.result, rejected(MLDSA87_VERIFY_JET_COST));
}

#[test]
fn data_jets_match_go_reference() {
    use core::cmp::Ordering::{Equal, Greater, Less};

    let u128_cmp = evaluate_u128_cmp_jet;
    let bytes_cmp = evaluate_bytes_cmp_jet;

    for (name, got, want, accepted) in [
        ("add", evaluate_u64_checked_add_jet(2, 3), 5, true),
        (
            "add-overflow",
            evaluate_u64_checked_add_jet(u64::MAX, 1),
            0,
            false,
        ),
        ("sub", evaluate_u64_checked_sub_jet(5, 3), 2, true),
        (
            "sub-underflow",
            evaluate_u64_checked_sub_jet(3, 5),
            0,
            false,
        ),
        ("mul", evaluate_u64_checked_mul_jet(7, 6), 42, true),
        (
            "mul-overflow",
            evaluate_u64_checked_mul_jet(1 << 63, 2),
            0,
            false,
        ),
    ] {
        assert_eq!(got, u64_jet(want, accepted), "{name}");
    }

    assert_eq!(evaluate_u64_cmp_jet(1, 2), ordering_jet(Less, 1));
    assert_eq!(evaluate_u64_cmp_jet(2, 2), ordering_jet(Equal, 1));
    assert_eq!(evaluate_u64_cmp_jet(3, 2), ordering_jet(Greater, 1));

    for (name, got, want, accepted) in [
        (
            "add-carry",
            evaluate_u128_checked_add_jet(uint128(0, u64::MAX), uint128(0, 1)),
            uint128(1, 0),
            true,
        ),
        (
            "add-overflow",
            evaluate_u128_checked_add_jet(uint128(u64::MAX, u64::MAX), uint128(0, 1)),
            uint128(0, 0),
            false,
        ),
        (
            "sub-borrow",
            evaluate_u128_checked_sub_jet(uint128(1, 0), uint128(0, 1)),
            uint128(0, u64::MAX),
            true,
        ),
        (
            "sub-underflow",
            evaluate_u128_checked_sub_jet(uint128(0, 0), uint128(0, 1)),
            uint128(0, 0),
            false,
        ),
    ] {
        assert_eq!(got, u128_jet(want, accepted), "{name}");
    }

    assert_eq!(
        u128_cmp(uint128(1, 0), uint128(2, 0)),
        ordering_jet(Less, 1)
    );
    assert_eq!(
        u128_cmp(uint128(2, 3), uint128(2, 3)),
        ordering_jet(Equal, 1)
    );
    assert_eq!(
        u128_cmp(uint128(2, 4), uint128(2, 3)),
        ordering_jet(Greater, 1)
    );

    assert_eq!(evaluate_bytes_eq_jet(&[], &[]), bool_jet(true, 1));
    assert_eq!(
        evaluate_bytes_eq_jet(&[0x11; 33], &[0x11; 32]),
        bool_jet(false, 3)
    );
    assert_eq!(bytes_cmp(&[0xff], &[0x01]), ordering_jet(Greater, 2));
    assert_eq!(bytes_cmp(b"ab", b"abc"), ordering_jet(Less, 2));
    assert_eq!(bytes_cmp(b"abc", b"ab"), ordering_jet(Greater, 2));
    assert_eq!(bytes_cmp(b"abc", b"abc"), ordering_jet(Equal, 2));

    let mut src = b"abcdef".to_vec();
    let got = evaluate_bytes_slice_jet(&src, 2, 3);
    assert_eq!(got, bytes_jet(b"cde", true, 2));
    src[2] = b'X';
    assert_eq!(got.bytes, b"cde");
    assert_eq!(
        evaluate_bytes_slice_jet(&src, src.len() as u64, 0),
        bytes_jet(&[], true, 1)
    );
    assert_eq!(
        evaluate_bytes_slice_jet(&src, 5, 2),
        bytes_jet(&[], false, 2)
    );
    assert_eq!(
        evaluate_bytes_slice_jet(&src, u64::MAX, 1),
        bytes_jet(&[], false, 2)
    );
    let max_len = evaluate_bytes_slice_jet(&[], 0, u64::MAX);
    assert_eq!(
        (max_len.accepted, max_len.cost),
        (false, 1 + u64::MAX.div_ceil(32))
    );
}

fn uint128(hi: u64, lo: u64) -> Uint128 {
    Uint128 { lo, hi }
}

fn u64_jet(value: u64, accepted: bool) -> U64JetResult {
    U64JetResult {
        value,
        accepted,
        cost: 1,
    }
}

fn u128_jet(value: Uint128, accepted: bool) -> U128JetResult {
    U128JetResult {
        value,
        accepted,
        cost: 1,
    }
}

fn ordering_jet(ordering: core::cmp::Ordering, cost: u64) -> OrderingJetResult {
    OrderingJetResult { ordering, cost }
}

fn bool_jet(value: bool, cost: u64) -> BoolJetResult {
    BoolJetResult { value, cost }
}

fn bytes_jet(bytes: &[u8], accepted: bool, cost: u64) -> BytesJetResult {
    BytesJetResult {
        bytes: bytes.to_vec(),
        accepted,
        cost,
    }
}

#[test]
#[rustfmt::skip]
fn evaluate_charges_decoded_program_steps() {
    for (program, witness, cost) in [("24", "", 1), ("8900", "", 2), ("c1220f0100", "", 4), ("c1d21014", "00", 4)] {
        assert_eq!(decoded(program, witness).evaluate(EvalOptions::default()).unwrap(), EvalResult { accepted: true, cost: cost * STEP_COST });
    }
}

#[test]
fn evaluate_memory_bounds_match_go_reference() {
    for frames in [
        vec![MAX_FRAME_BYTES * 8],
        repeated(
            MAX_FRAME_BYTES * 8,
            (MAX_LIVE_MEMORY_BYTES / MAX_FRAME_BYTES) as usize,
        ),
    ] {
        let got = internal_program(1, false, None, frames)
            .evaluate(EvalOptions::default())
            .unwrap();
        assert_eq!(got, ok(STEP_COST));
    }
    for frames in [
        vec![MAX_FRAME_BYTES * 8 + 1],
        [
            repeated(
                MAX_FRAME_BYTES * 8,
                (MAX_LIVE_MEMORY_BYTES / MAX_FRAME_BYTES) as usize,
            ),
            vec![8],
        ]
        .concat(),
    ] {
        assert_eq!(
            internal_program(1, false, None, frames)
                .evaluate(EvalOptions::default())
                .unwrap_err()
                .code,
            ErrorCode::BudgetExceeded
        );
    }

    let calls = std::cell::Cell::new(0);
    let mut program = decoded("60", "");
    program.frame_bit_widths = vec![MAX_FRAME_BYTES * 8 + 1];
    let hook = |_: Jet| {
        calls.set(calls.get() + 1);
        Ok(ok(1))
    };
    assert_eq!(
        program.evaluate(with_jet_hook(&hook)).unwrap_err().code,
        ErrorCode::BudgetExceeded
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn decode_populates_memory_schedule() {
    for (program, witness) in [("24", ""), ("c1d21014", "00"), ("60", ""), ("70", "")] {
        let program = decoded(program, witness);
        assert!(!program.frame_bit_widths.is_empty());
        check_memory_bounds(&program.frame_bit_widths).unwrap();
    }
}

#[test]
fn evaluate_memory_error_class_priority() {
    let over_frame = vec![MAX_FRAME_BYTES * 8 + 1];
    let mut undecoded = internal_program(1, false, None, over_frame.clone());
    undecoded.decoded = false;
    assert_eq!(
        undecoded.evaluate(EvalOptions::default()).unwrap_err().code,
        ErrorCode::Decode
    );
    assert_eq!(
        internal_program(0, false, None, over_frame.clone())
            .evaluate(EvalOptions::default())
            .unwrap_err()
            .code,
        ErrorCode::Decode
    );
    assert_eq!(
        internal_program(0, true, Some((0xffff, 0x00)), over_frame.clone())
            .evaluate(EvalOptions::default())
            .unwrap_err()
            .code,
        ErrorCode::Decode
    );
    assert_eq!(
        internal_program(1, false, None, over_frame)
            .evaluate(EvalOptions::default())
            .unwrap_err()
            .code,
        ErrorCode::BudgetExceeded
    );
}

#[test]
fn evaluate_jet_requires_cost_hook() {
    let err = decoded("60", "")
        .evaluate(EvalOptions::default())
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::JetDisallowed);
    assert_eq!(err.result, EvalResult::default());
}

#[test]
#[rustfmt::skip]
fn evaluate_ignores_public_jet_without_decoded_key() {
    let hook = |_: Jet| Ok(ok(1));
    let program = Program { jet: Some(lookup_jet(0x0001, 0x00).unwrap()), ..internal_program(0, false, None, vec![]) };
    assert_eq!(program.evaluate(with_jet_hook(&hook)).unwrap_err().code, ErrorCode::Decode);
}

#[test]
#[rustfmt::skip]
fn evaluate_uses_decoded_jet_identity() {
    let mut program = decoded("60", "");
    let original = program.jet.unwrap();
    program.jet = Some(Jet { name: "forged", ..original });
    let hook = |jet: Jet| {
        assert_eq!((jet.id, jet.sub_op, jet.name), (0x0001, 0x00, "sha3_256"));
        Ok(ok(1))
    };
    assert_eq!(program.evaluate(with_jet_hook(&hook)).unwrap(), ok(1));
}

#[test]
#[rustfmt::skip]
fn evaluate_jet_cost_hook_cap_boundary() {
    let program = decoded("60", "");
    for cost in [0, MAX_EXEC_COST - 1, MAX_EXEC_COST] {
        let hook = |_: Jet| Ok(ok(cost));
        assert_eq!(program.evaluate(with_jet_hook(&hook)).unwrap(), ok(cost));
    }
    let hook = |_: Jet| Ok(ok(MAX_EXEC_COST + 1));
    let err = program.evaluate(with_jet_hook(&hook)).unwrap_err();
    assert_eq!(err.code, ErrorCode::BudgetExceeded);
    assert_eq!(err.result, ok(MAX_EXEC_COST));
}

#[test]
#[rustfmt::skip]
fn evaluate_jet_rejects_failed_hook_result() {
    let program = decoded("60", "");
    let hook = |_: Jet| Ok(rejected(3));
    let err = program.evaluate(with_jet_hook(&hook)).unwrap_err();
    assert_eq!(err.code, ErrorCode::Rejected);
    assert_eq!(err.result, rejected(3));
}

#[test]
#[rustfmt::skip]
fn evaluate_internal_fail_closed_paths() {
    assert_eq!(internal_program(0, false, None, vec![]).evaluate(EvalOptions::default()).unwrap_err().code, ErrorCode::Decode);
    let hook = |_: Jet| Ok(ok(0));
    assert_eq!(internal_program(0, true, Some((0xffff, 0x00)), vec![]).evaluate(with_jet_hook(&hook)).unwrap_err().code, ErrorCode::Decode);
    let hook_error = |_: Jet| Err(EvalError { code: ErrorCode::Decode, result: ok(9) });
    let err = decoded("60", "").evaluate(with_jet_hook(&hook_error)).unwrap_err();
    assert_eq!(err.code, ErrorCode::Decode);
    assert_eq!(err.result, EvalResult::default());
    let err = internal_program(MAX_EXEC_COST / STEP_COST + 1, false, None, vec![])
        .evaluate(EvalOptions::default())
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BudgetExceeded);
    assert_eq!(err.result, ok(MAX_EXEC_COST));
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn decoded(program: &str, witness: &str) -> Program {
    decode(&hx(program), &hx(witness), opts(SEMANTICS_VERSION, "")).unwrap()
}

#[rustfmt::skip]
fn ok(cost: u64) -> EvalResult { EvalResult { accepted: true, cost } }

#[rustfmt::skip]
fn rejected(cost: u64) -> EvalResult { EvalResult { accepted: false, cost } }

#[rustfmt::skip]
fn mldsa_result(verified: bool) -> Mldsa87VerifyJetResult { Mldsa87VerifyJetResult { verified, cost: MLDSA87_VERIFY_JET_COST } }

#[rustfmt::skip]
fn with_jet_hook<'a>(hook: &'a dyn Fn(Jet) -> Result<EvalResult, EvalError>) -> EvalOptions<'a> { EvalOptions { jet_evaluator: Some(hook) } }

#[rustfmt::skip]
fn internal_program(eval_steps: u64, has_jet: bool, jet_key: Option<JetKey>, frame_bit_widths: Vec<u64>) -> Program {
    Program { cmr: [0; 32], jet: None, needs_witness: false, max_witness_len: 0, witness_kind: WitnessKind::None, eval_steps, decoded: true, has_jet, jet_key, frame_bit_widths }
}

fn repeated(value: u64, count: usize) -> Vec<u64> {
    vec![value; count]
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

fn exec_corpus_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../../../conformance/fixtures/protocol/simplicity_exec_corpus_v1.json");
    path
}

fn crypto_jets_corpus_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../../../conformance/fixtures/protocol/simplicity_crypto_jets_corpus_v1.json");
    path
}

fn data_jets_corpus_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../../../conformance/fixtures/protocol/simplicity_data_jets_corpus_v1.json");
    path
}

fn jets_registry_corpus_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../../../conformance/fixtures/protocol/simplicity_jets_registry_corpus_v1.json");
    path
}

fn evaluate_shared_exec_case(case: &SharedExecCase) -> Result<EvalResult, EvalError> {
    let program = if !case.program_hex.is_empty() {
        decode(
            &hx(&case.program_hex),
            &hx(&case.witness_hex),
            opts(SEMANTICS_VERSION, ""),
        )
        .map_err(|err| EvalError::new(err.code))?
    } else {
        internal_program(case.eval_steps, false, None, case.frame_bit_widths.clone())
    };
    if program.has_jet {
        let hook = |_: Jet| {
            Ok(EvalResult {
                accepted: case.jet_accepted,
                cost: case.jet_cost,
            })
        };
        program.evaluate(with_jet_hook(&hook))
    } else {
        program.evaluate(EvalOptions::default())
    }
}

fn error_code(s: &str) -> Option<ErrorCode> {
    [
        ErrorCode::Decode,
        ErrorCode::ProgramTooLarge,
        ErrorCode::CmrMismatch,
        ErrorCode::JetDisallowed,
        ErrorCode::BudgetExceeded,
        ErrorCode::Rejected,
    ]
    .into_iter()
    .find(|code| code.as_str() == s)
}

#[test]
fn descriptor_hash_access_cost_boundaries() {
    // Mirrors Go TestDescriptorHashAccessCostBoundaries: pin the in-range cost, the
    // exact MAX_EXEC_COST boundary (no error), the one-past budget reject, and the
    // pre-charge overflow guard that the txcontext oversize test never reaches.
    assert_eq!(
        descriptor_hash_access_cost(3).expect("in range"),
        DESCRIPTOR_HASH_BASE_COST + 3 * DESCRIPTOR_HASH_BYTE_COST
    );
    let max_len = (MAX_EXEC_COST - DESCRIPTOR_HASH_BASE_COST) / DESCRIPTOR_HASH_BYTE_COST;
    assert_eq!(
        descriptor_hash_access_cost(max_len).expect("max boundary"),
        MAX_EXEC_COST
    );
    assert_eq!(
        descriptor_hash_access_cost(max_len + 1)
            .expect_err("over budget")
            .code,
        ErrorCode::BudgetExceeded
    );
    assert_eq!(
        descriptor_hash_access_cost(u64::MAX)
            .expect_err("overflow guard")
            .code,
        ErrorCode::BudgetExceeded
    );
}
