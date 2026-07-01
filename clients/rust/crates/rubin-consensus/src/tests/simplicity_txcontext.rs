use super::*;
use crate::compactsize::encode_compact_size;
use crate::constants::{
    COV_TYPE_CORE_SIMPLICITY, COV_TYPE_P2PK, MAX_TX_INPUTS, MAX_TX_OUTPUTS, SIGHASH_ALL,
};
use crate::error::ErrorCode;
use crate::tx::{Tx, TxInput, TxOutput};
use crate::txcontext::Uint128;
use crate::utxo_basic::UtxoEntry;

fn covenant(program_cmr: [u8; 32], state: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&program_cmr);
    encode_compact_size(state.len() as u64, &mut out);
    out.extend_from_slice(state);
    out
}

fn tx_with(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Tx {
    Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 1,
        inputs,
        outputs,
        locktime: 0,
        witness: vec![],
        da_payload: vec![],
        da_commit_core: None,
        da_chunk_core: None,
    }
}

fn input() -> TxInput {
    TxInput {
        prev_txid: [0u8; 32],
        prev_vout: 0,
        script_sig: vec![],
        sequence: 0,
    }
}

fn utxo(value: u64, covenant_type: u16, covenant_data: Vec<u8>) -> UtxoEntry {
    UtxoEntry {
        value,
        covenant_type,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    }
}

fn p2pk(value: u64) -> TxOutput {
    TxOutput {
        value,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: vec![],
    }
}

#[test]
fn build_returns_none_and_rejects_bad_counts() {
    // No CORE_SIMPLICITY input -> no context.
    let tx = tx_with(vec![input()], vec![p2pk(5)]);
    let resolved = vec![utxo(10, COV_TYPE_P2PK, vec![])];
    assert!(build_simplicity_tx_context(&tx, &resolved, 77, [0u8; 32])
        .expect("build")
        .is_none());

    // Resolved-input count mismatch.
    let tx2 = tx_with(vec![input(), input()], vec![]);
    let err = build_simplicity_tx_context(&tx2, &resolved, 1, [0u8; 32]).expect_err("mismatch");
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(
        err.msg,
        "simplicity txcontext resolved input count mismatch"
    );

    // Input-count overflow.
    let n = MAX_TX_INPUTS as usize + 1;
    let in_over = tx_with(vec![input(); n], vec![]);
    let in_res = vec![utxo(0, COV_TYPE_P2PK, vec![]); n];
    let err = build_simplicity_tx_context(&in_over, &in_res, 1, [0u8; 32]).expect_err("in over");
    assert_eq!(err.msg, "simplicity txcontext input_count overflow");

    // Output-count overflow.
    let out_over = tx_with(vec![input()], vec![p2pk(0); MAX_TX_OUTPUTS as usize + 1]);
    let out_res = vec![utxo(0, COV_TYPE_P2PK, vec![])];
    let err = build_simplicity_tx_context(&out_over, &out_res, 1, [0u8; 32]).expect_err("out over");
    assert_eq!(err.msg, "simplicity txcontext output_count overflow");
}

#[test]
fn build_populates_base_views_self_and_fresh_copies() {
    let chain_id = [0x11u8; 32];
    let cmr = [0xaau8; 32];
    let digest = [0x42u8; 32];
    let state = [1u8, 2, 3];
    let mut src = covenant(cmr, &state);

    let mut tx = tx_with(vec![input(), input()], vec![p2pk(u64::MAX), p2pk(1)]);
    tx.tx_kind = 2;
    tx.tx_nonce = 99;
    tx.locktime = 12345;
    let resolved = vec![
        utxo(u64::MAX, COV_TYPE_CORE_SIMPLICITY, src.clone()),
        utxo(1, COV_TYPE_P2PK, vec![]),
    ];

    let ctx = build_simplicity_tx_context(&tx, &resolved, 700, chain_id)
        .expect("build")
        .expect("context");
    src[0] = 0xff; // mutating the source after build must not alias into ctx

    assert_eq!(ctx.base.chain_id, chain_id);
    assert_eq!(ctx.base.height, 700);
    assert_eq!(ctx.base.tx_kind, 2);
    assert_eq!(ctx.base.tx_nonce, 99);
    assert_eq!(ctx.base.locktime, 12345);
    assert_eq!(ctx.base.input_count, 2);
    assert_eq!(ctx.base.output_count, 2);
    // u64::MAX + 1 == 2^64 -> hi carry.
    assert_eq!(ctx.base.total_in, Uint128 { lo: 0, hi: 1 });
    assert_eq!(ctx.base.total_out, Uint128 { lo: 0, hi: 1 });

    let inputs = ctx.input_views();
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0].value, u64::MAX);
    assert_eq!(inputs[0].covenant_type, COV_TYPE_CORE_SIMPLICITY);
    assert_eq!(
        ctx.output_views()[1],
        SimplicityTxContextIoView {
            value: 1,
            covenant_type: COV_TYPE_P2PK,
        }
    );

    let mut self_view = ctx.self_view(0, SIGHASH_ALL, digest).expect("self");
    assert_eq!(self_view.input_index, 0);
    assert_eq!(self_view.self_value, u64::MAX);
    assert_eq!(self_view.sighash_type, SIGHASH_ALL);
    assert_eq!(self_view.self_program_cmr, cmr);
    assert_eq!(self_view.digest32, digest);
    assert_eq!(self_view.self_state, state.to_vec());

    // Accessors return fresh copies: local mutation must not leak back.
    self_view.self_state.push(0xaa);
    let mut views = ctx.input_views();
    views[0].value = 0;
    assert_eq!(
        ctx.self_view(0, SIGHASH_ALL, digest).unwrap().self_state,
        state.to_vec()
    );
    assert_eq!(ctx.input_views()[0].value, u64::MAX);

    // Self view fail-closed: input 1 is P2PK, input 2 is out of range.
    let e1 = ctx.self_view(1, SIGHASH_ALL, digest).expect_err("non-core");
    assert_eq!(e1.code, ErrorCode::TxErrCovenantTypeInvalid);
    let e2 = ctx
        .self_view(2, SIGHASH_ALL, digest)
        .expect_err("out of range");
    assert_eq!(e2.code, ErrorCode::TxErrParse);
}

#[test]
fn build_accepts_empty_state_without_aliasing() {
    let cmr = [0x51u8; 32];
    let mut src = covenant(cmr, &[]);
    let tx = tx_with(vec![input()], vec![]);
    let resolved = vec![utxo(1, COV_TYPE_CORE_SIMPLICITY, src.clone())];

    let ctx = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32])
        .expect("build")
        .expect("context");
    src[0] = 0xff;

    let self_view = ctx.self_view(0, SIGHASH_ALL, [0u8; 32]).expect("self");
    assert_eq!(self_view.self_program_cmr, cmr);
    assert!(self_view.self_state.is_empty());
}

#[test]
fn build_fails_closed_on_malformed_self_covenant() {
    let tx = tx_with(vec![input()], vec![]);
    let resolved = vec![utxo(1, COV_TYPE_CORE_SIMPLICITY, vec![0x01])];
    let err = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32]).expect_err("malformed");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert_eq!(err.msg, "CORE_SIMPLICITY program_cmr parse failure");
}

#[test]
fn build_rejects_zero_value_core_simplicity_input() {
    // Mirrors Go: parse checks value > 0 before structure, so a structurally
    // valid but zero-value CORE_SIMPLICITY input is rejected at build time.
    let tx = tx_with(vec![input()], vec![]);
    let resolved = vec![utxo(
        0,
        COV_TYPE_CORE_SIMPLICITY,
        covenant([0x77u8; 32], &[]),
    )];
    let err = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32]).expect_err("zero value");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert_eq!(err.msg, "CORE_SIMPLICITY value must be > 0");
}
