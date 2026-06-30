use super::*;
use crate::compactsize::encode_compact_size;
use crate::constants::{COV_TYPE_CORE_SIMPLICITY, MAX_SIMPLICITY_STATE_BYTES, SUITE_ID_ML_DSA_87};
use crate::error::ErrorCode;
use crate::suite_registry::{DefaultRotationProvider, NativeSuiteSet, RotationProvider};
use crate::tx::{Tx, TxOutput};

// Rotation provider that reports the Simplicity deployment active at/above a
// threshold height, mirroring Go's testRotationProvider{simplicityActiveHeight}.
// Suite sets fall back to the default ({ML-DSA-87}) so unrelated P2PK creation
// rules are intact.
struct ActiveSimplicity {
    active_from: u64,
}
impl RotationProvider for ActiveSimplicity {
    fn native_create_suites(&self, h: u64) -> NativeSuiteSet {
        DefaultRotationProvider.native_create_suites(h)
    }
    fn native_spend_suites(&self, h: u64) -> NativeSuiteSet {
        DefaultRotationProvider.native_spend_suites(h)
    }
    fn simplicity_active_at_height(&self, h: u64) -> bool {
        h >= self.active_from
    }
}

fn encode_simplicity_covenant_data(program_cmr: [u8; 32], state: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 1 + state.len());
    out.extend_from_slice(&program_cmr);
    encode_compact_size(state.len() as u64, &mut out);
    out.extend_from_slice(state);
    out
}

fn err_msg(e: &crate::error::TxError) -> String {
    format!("{e}")
}

fn tx_with_outputs(outputs: Vec<TxOutput>) -> Tx {
    Tx {
        version: 1,
        tx_kind: 0x00,
        tx_nonce: 1,
        inputs: vec![],
        outputs,
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    }
}

fn simplicity_output(value: u64, covenant_data: Vec<u8>) -> TxOutput {
    TxOutput {
        value,
        covenant_type: COV_TYPE_CORE_SIMPLICITY,
        covenant_data,
    }
}

// covenant_data = program_cmr:32 || state_len:CompactSize || state; value>0;
// state_len<=512; exact total length. Mirrors Go validateCoreSimplicityCovenantData.
#[test]
fn covenant_data_validation_cases() {
    let cmr = [0xab; 32];
    let max = MAX_SIMPLICITY_STATE_BYTES as usize;
    let ok_empty = encode_simplicity_covenant_data(cmr, &[]);
    let ok_max = encode_simplicity_covenant_data(cmr, &vec![0u8; max]);
    let over = encode_simplicity_covenant_data(cmr, &vec![0u8; max + 1]);
    let mut trailing = encode_simplicity_covenant_data(cmr, &[0x09]);
    trailing.push(0xff); // extra byte past the declared state
    let mut truncated = vec![0x22; 32]; // CMR + state_len=3 but only 2 state bytes
    encode_compact_size(3, &mut truncated);
    truncated.extend_from_slice(&[0x01, 0x02]);
    let mut nonminimal = vec![0xa5; 32]; // state_len 252 in non-minimal 3-byte form
    nonminimal.extend_from_slice(&[0xfd, 0xfc, 0x00]);
    nonminimal.extend_from_slice(&vec![0u8; 0xfc]);

    let cases: &[(u64, &[u8], Option<&str>)] = &[
        (1, &ok_empty, None),
        (1, &ok_max, None),
        (0, &ok_empty, Some("value must be > 0")),
        (1, &[0u8; 31], Some("program_cmr parse failure")),
        (1, &nonminimal, Some("state_len parse failure")),
        (1, &over, Some("state_len too large")),
        (1, &truncated, Some("state parse failure")),
        (1, &trailing, Some("covenant_data length mismatch")),
    ];
    for (i, (value, data, want)) in cases.iter().enumerate() {
        let res = validate_core_simplicity_covenant_data(*value, data);
        match want {
            None => assert!(res.is_ok(), "case {i}: expected ok, got {res:?}"),
            Some(sub) => {
                let e = res.unwrap_err();
                assert_eq!(e.code, ErrorCode::TxErrCovenantTypeInvalid, "case {i}");
                assert!(err_msg(&e).contains(sub), "case {i}: got {}", err_msg(&e));
            }
        }
    }
}

// End-to-end through the genesis dispatch. Mirrors Go
// TestValidateTxCovenantsGenesis_CoreSimplicityActive: the deployment-active
// gate runs before any structural parse (so an inactive provider rejects even
// malformed data with "deployment not active"), and an active provider accepts
// well-formed data while still surfacing structural errors.
#[test]
fn genesis_deployment_gate() {
    let active = ActiveSimplicity { active_from: 10 };
    let valid = encode_simplicity_covenant_data([0x44; 32], &[0x01, 0x02]);

    // The active provider only flips the Simplicity deployment flag; its native
    // create/spend suites stay the default ({ML-DSA-87}), so P2PK rotation is
    // unaffected by the gate.
    assert!(active.native_create_suites(10).contains(SUITE_ID_ML_DSA_87));
    assert!(active.native_spend_suites(10).contains(SUITE_ID_ML_DSA_87));

    // Inactive (default): rejected at the gate, before any covenant_data parse.
    let tx = tx_with_outputs(vec![simplicity_output(1, valid.clone())]);
    let e = crate::validate_tx_covenants_genesis(&tx, 10, None).unwrap_err();
    assert_eq!(e.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err_msg(&e).contains("deployment not active"));

    // Inactive + malformed: still the gate message, not the structural one.
    let bad_inactive = tx_with_outputs(vec![simplicity_output(1, vec![0u8; 10])]);
    let e = crate::validate_tx_covenants_genesis(&bad_inactive, 10, None).unwrap_err();
    assert!(err_msg(&e).contains("deployment not active"));

    // Active provider, but BELOW its activation height: still "not active".
    let e = crate::validate_tx_covenants_genesis(&tx, 9, Some(&active)).unwrap_err();
    assert!(err_msg(&e).contains("deployment not active"));

    // Production DescriptorRotationProvider does not wire a deployment, so it
    // inherits the default-false seam: fail-closed even at a high height.
    let descriptor = crate::suite_registry::DescriptorRotationProvider {
        descriptor: crate::suite_registry::CryptoRotationDescriptor {
            name: "t".into(),
            old_suite_id: crate::constants::SUITE_ID_ML_DSA_87,
            new_suite_id: 0x02,
            create_height: 1,
            spend_height: 2,
            sunset_height: 0,
        },
    };
    let e = crate::validate_tx_covenants_genesis(&tx, 100, Some(&descriptor)).unwrap_err();
    assert!(err_msg(&e).contains("deployment not active"));

    // Active at/above the activation height: a well-formed output is accepted.
    assert!(crate::validate_tx_covenants_genesis(&tx, 10, Some(&active)).is_ok());

    // Active + value 0 / malformed: structural errors surface after the gate.
    let zero = tx_with_outputs(vec![simplicity_output(0, valid)]);
    let e = crate::validate_tx_covenants_genesis(&zero, 10, Some(&active)).unwrap_err();
    assert!(err_msg(&e).contains("value must be > 0"));
    let bad = tx_with_outputs(vec![simplicity_output(1, vec![0u8; 10])]);
    let e = crate::validate_tx_covenants_genesis(&bad, 10, Some(&active)).unwrap_err();
    assert!(err_msg(&e).contains("program_cmr parse failure"));
}
