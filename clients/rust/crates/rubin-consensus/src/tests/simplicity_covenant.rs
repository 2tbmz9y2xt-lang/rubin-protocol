use super::*;
use crate::compactsize::encode_compact_size;
use crate::constants::{COV_TYPE_CORE_SIMPLICITY, MAX_SIMPLICITY_STATE_BYTES};
use crate::error::ErrorCode;
use crate::tx::{Tx, TxOutput};

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

// End-to-end through the genesis dispatch: creation is fail-closed in this slice
// ("creation not enabled"); malformed covenant_data surfaces the structural
// error first. The deployment-active gate that turns this into conditional
// acceptance lands in RUB-590.
#[test]
fn genesis_arm_fail_closed() {
    let data = encode_simplicity_covenant_data([0x44; 32], &[0x01, 0x02]);
    let tx = tx_with_outputs(vec![simplicity_output(1, data)]);
    let e = crate::validate_tx_covenants_genesis(&tx, 10, None).unwrap_err();
    assert_eq!(e.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err_msg(&e).contains("creation not enabled"));

    let bad = tx_with_outputs(vec![simplicity_output(1, vec![0u8; 10])]);
    let e = crate::validate_tx_covenants_genesis(&bad, 10, None).unwrap_err();
    assert_eq!(e.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err_msg(&e).contains("program_cmr parse failure"));
}
