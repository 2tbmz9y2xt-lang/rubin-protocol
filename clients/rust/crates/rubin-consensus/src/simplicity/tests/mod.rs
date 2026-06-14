use super::*;

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
fn decode_vectors_match_go_reference() {
    for (program, witness, version, covenant, want_cmr, want_err) in DECODE_CASES {
        let got = decode(&hx(program), &hx(witness), opts(*version, covenant));
        match want_err {
            Some(code) => assert_eq!(got.unwrap_err().code, *code),
            None => assert_eq!(got.unwrap().cmr, hex32(want_cmr.unwrap()).unwrap()),
        }
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
fn jet_rows_and_hashes_match_go_reference() {
    assert_eq!(JET_ROWS.len(), 12);
    for row in JET_ROWS {
        assert!(lookup_jet(row.id, row.sub_op).is_some(), "missing jet row");
    }
    let sha3 = lookup_jet(0x0001, 0).unwrap();
    assert_eq!(
        (sha3.name, sha3.selector_bit_len, sha3.selector_padded),
        ("sha3_256", 2, [0x00].as_slice())
    );
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

fn opts(version: u32, covenant: &str) -> DecodeOptions {
    DecodeOptions {
        semantics_version: version,
        covenant_program_cmr: optional_cmr(covenant),
    }
}

fn optional_cmr(s: &str) -> Option<[u8; 32]> {
    (!s.is_empty()).then(|| hex32(s).unwrap())
}
