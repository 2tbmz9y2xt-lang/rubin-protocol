use std::collections::BTreeMap;

use crate::constants::{COV_TYPE_CORE_EXT, COV_TYPE_P2PK};
use crate::core_ext::{CoreExtActiveProfile, CoreExtProfiles, CoreExtVerificationBinding};
use crate::error::ErrorCode;
use crate::tx::{Tx, TxInput, TxOutput};
use crate::txcontext::{
    build_tx_context, build_tx_context_output_ext_id_cache, collect_txcontext_ext_ids,
    TxContextContinuing, Uint128,
};
use crate::utxo_basic::UtxoEntry;

const TXCONTEXT_TOO_MANY_CONTINUING_OUTPUTS: &str =
    "too many continuing outputs for txcontext ext_id";

fn core_ext_covdata(ext_id: u16, payload: &[u8]) -> Vec<u8> {
    crate::core_ext::encode_core_ext_covenant_data(ext_id, payload)
        .expect("CORE_EXT covenant_data encode")
}

fn static_profiles(entries: &[(u16, bool)]) -> CoreExtProfiles {
    CoreExtProfiles {
        active: entries
            .iter()
            .map(|(ext_id, tx_context_enabled)| active_profile(*ext_id, *tx_context_enabled, 0x42))
            .collect(),
    }
}

fn active_profile(ext_id: u16, tx_context_enabled: bool, suite_id: u8) -> CoreExtActiveProfile {
    CoreExtActiveProfile {
        ext_id,
        tx_context_enabled,
        allowed_suite_ids: vec![suite_id],
        verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
        verify_sig_ext_tx_context_fn: None,
        binding_descriptor: format!("accept-{suite_id}").into_bytes(),
        ext_payload_schema: format!("schema-{suite_id}").into_bytes(),
    }
}

fn tx_input(byte: u8, prev_vout: u32) -> TxInput {
    TxInput {
        prev_txid: [byte; 32],
        prev_vout,
        script_sig: vec![],
        sequence: 0,
    }
}

fn tx_output(value: u64, covenant_type: u16, covenant_data: Vec<u8>) -> TxOutput {
    TxOutput {
        value,
        covenant_type,
        covenant_data,
    }
}

fn core_ext_output(value: u64, ext_id: u16, payload: &[u8]) -> TxOutput {
    tx_output(value, COV_TYPE_CORE_EXT, core_ext_covdata(ext_id, payload))
}

fn core_ext_utxo(value: u64, ext_id: u16, payload: &[u8]) -> UtxoEntry {
    UtxoEntry {
        value,
        covenant_type: COV_TYPE_CORE_EXT,
        covenant_data: core_ext_covdata(ext_id, payload),
        creation_height: 0,
        created_by_coinbase: false,
    }
}

fn p2pk_utxo(value: u64, covenant_data: Vec<u8>) -> UtxoEntry {
    UtxoEntry {
        value,
        covenant_type: COV_TYPE_P2PK,
        covenant_data,
        creation_height: 0,
        created_by_coinbase: false,
    }
}

fn tx_with(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Tx {
    Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 1,
        inputs,
        outputs,
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![],
        da_payload: vec![],
    }
}

fn one_input_tx(output: TxOutput) -> Tx {
    tx_with(vec![tx_input(0, 0)], vec![output])
}

fn deterministic_context_tx() -> Tx {
    tx_with(
        vec![tx_input(1, 0), tx_input(2, 1), tx_input(3, 2)],
        vec![
            core_ext_output(11, 7, &[0x07, 0x01]),
            tx_output(12, COV_TYPE_P2PK, vec![0x01]),
            core_ext_output(13, 5, &[0x05, 0x01]),
            core_ext_output(14, 7, &[0x07, 0x02]),
            core_ext_output(15, 5, &[0x05, 0x02]),
        ],
    )
}

fn deterministic_context_inputs() -> Vec<UtxoEntry> {
    vec![
        core_ext_utxo(100, 7, &[0xaa]),
        core_ext_utxo(200, 5, &[0xbb]),
        p2pk_utxo(300, vec![0x01]),
    ]
}

fn overflow_context_tx() -> Tx {
    tx_with(
        vec![tx_input(1, 0), tx_input(2, 1)],
        vec![
            core_ext_output(1, 9, &[0x91]),
            core_ext_output(2, 7, &[0x71]),
            core_ext_output(3, 9, &[0x92]),
            core_ext_output(4, 7, &[0x72]),
            core_ext_output(5, 7, &[0x73]),
            core_ext_output(6, 9, &[0x93]),
        ],
    )
}

fn overflow_context_inputs() -> Vec<UtxoEntry> {
    vec![
        core_ext_utxo(100, 9, &[0xaa]),
        core_ext_utxo(200, 7, &[0xbb]),
    ]
}

#[test]
fn build_tx_context_output_ext_id_cache_rejects_malformed_output() {
    let tx = one_input_tx(tx_output(10, COV_TYPE_CORE_EXT, vec![0x01]));

    let err = build_tx_context_output_ext_id_cache(&tx).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn txcontext_get_output_checked_rejects_missing_slot() {
    let continuing = TxContextContinuing {
        continuing_output_count: 1,
        continuing_outputs: [None, None],
    };

    let err = continuing.get_output_checked(0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert_eq!(err.msg, "txcontext continuing output missing");
}

#[test]
fn build_tx_context_returns_none_without_txcontext_enabled_inputs() {
    let tx = one_input_tx(core_ext_output(33, 7, &[0xaa]));
    let resolved_inputs = vec![core_ext_utxo(50, 7, &[0xbb])];

    let cache = build_tx_context_output_ext_id_cache(&tx).unwrap();
    let bundle = build_tx_context(
        &tx,
        &resolved_inputs,
        Some(&cache),
        12,
        &static_profiles(&[(7, false)]),
    )
    .unwrap();
    assert!(bundle.is_none());
}

#[test]
fn collect_txcontext_ext_ids_skips_disabled_profiles_and_deduplicates() {
    let resolved_inputs = vec![
        core_ext_utxo(11, 9, &[0x90]),
        core_ext_utxo(12, 7, &[0x71]),
        core_ext_utxo(13, 7, &[0x72]),
        p2pk_utxo(14, vec![]),
    ];

    let ext_ids =
        collect_txcontext_ext_ids(&resolved_inputs, &static_profiles(&[(7, true), (9, false)]))
            .expect("collect ext_ids");
    assert_eq!(ext_ids, vec![7]);
}

#[test]
fn collect_txcontext_ext_ids_rejects_duplicate_active_profiles() {
    let resolved_inputs = vec![core_ext_utxo(11, 7, &[0x71])];
    let profiles = CoreExtProfiles {
        active: vec![active_profile(7, true, 0x42), active_profile(7, true, 0x43)],
    };

    let err = collect_txcontext_ext_ids(&resolved_inputs, &profiles).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert_eq!(err.msg, "CORE_EXT multiple ACTIVE profiles for ext_id");
}

#[test]
fn build_tx_context_requires_output_cache_when_enabled() {
    let tx = one_input_tx(core_ext_output(33, 7, &[]));
    let resolved_inputs = vec![core_ext_utxo(50, 7, &[0xbb])];

    let err = build_tx_context(
        &tx,
        &resolved_inputs,
        None,
        12,
        &static_profiles(&[(7, true)]),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn build_tx_context_rejects_resolved_input_count_mismatch() {
    let tx = one_input_tx(core_ext_output(33, 7, &[]));

    let err = build_tx_context(
        &tx,
        &[],
        Some(&BTreeMap::new()),
        12,
        &static_profiles(&[(7, true)]),
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "txcontext resolved input count mismatch");
}

#[test]
fn build_tx_context_keeps_enabled_ext_id_with_empty_continuations() {
    let tx = one_input_tx(tx_output(33, COV_TYPE_P2PK, vec![0x01]));
    let resolved_inputs = vec![core_ext_utxo(50, 7, &[0xbb])];

    let cache = build_tx_context_output_ext_id_cache(&tx).expect("cache");
    let bundle = build_tx_context(
        &tx,
        &resolved_inputs,
        Some(&cache),
        12,
        &static_profiles(&[(7, true)]),
    )
    .unwrap()
    .expect("bundle");

    assert_eq!(bundle.sorted_ext_ids(), vec![7]);
    let continuing = bundle.get_continuing(7).expect("ext 7");
    assert_eq!(continuing.continuing_output_count, 0);
    assert!(continuing.valid_outputs().is_empty());
}

#[test]
fn build_tx_context_builds_base_and_deterministic_continuations() {
    let tx = deterministic_context_tx();
    let resolved_inputs = deterministic_context_inputs();
    let cache = build_tx_context_output_ext_id_cache(&tx).unwrap();
    let bundle = build_tx_context(
        &tx,
        &resolved_inputs,
        Some(&cache),
        222,
        &static_profiles(&[(5, true), (7, true)]),
    )
    .unwrap()
    .expect("bundle");

    assert_eq!(bundle.base.total_in, Uint128 { lo: 600, hi: 0 });
    assert_eq!(bundle.base.total_out, Uint128 { lo: 65, hi: 0 });
    assert_eq!(bundle.base.height, 222);
    assert_eq!(bundle.sorted_ext_ids(), vec![5, 7]);

    let ext5 = bundle.get_continuing(5).expect("ext 5");
    assert_eq!(ext5.continuing_output_count, 2);
    assert_eq!(ext5.get_output_checked(0).unwrap().value, 13);
    assert_eq!(
        ext5.get_output_checked(0).unwrap().ext_payload.as_ref(),
        &[0x05, 0x01]
    );
    assert_eq!(ext5.get_output_checked(1).unwrap().value, 15);

    let ext7 = bundle.get_continuing(7).expect("ext 7");
    assert_eq!(ext7.continuing_output_count, 2);
    assert_eq!(ext7.get_output_checked(0).unwrap().value, 11);
    assert_eq!(ext7.get_output_checked(1).unwrap().value, 14);
}

#[test]
fn build_tx_context_preserves_empty_payload_as_empty_vec() {
    let tx = one_input_tx(core_ext_output(33, 7, &[]));
    let resolved_inputs = vec![core_ext_utxo(50, 7, &[0xaa])];
    let cache = build_tx_context_output_ext_id_cache(&tx).unwrap();
    let bundle = build_tx_context(
        &tx,
        &resolved_inputs,
        Some(&cache),
        12,
        &static_profiles(&[(7, true)]),
    )
    .unwrap()
    .expect("bundle");

    let output = bundle
        .get_continuing(7)
        .unwrap()
        .get_output_checked(0)
        .unwrap()
        .ext_payload
        .clone();
    assert!(output.is_empty());
}

#[test]
fn build_tx_context_rejects_third_output_for_lowest_ext_id() {
    let tx = overflow_context_tx();
    let resolved_inputs = overflow_context_inputs();
    let cache = build_tx_context_output_ext_id_cache(&tx).unwrap();
    let err = build_tx_context(
        &tx,
        &resolved_inputs,
        Some(&cache),
        12,
        &static_profiles(&[(7, true), (9, true)]),
    )
    .unwrap_err();

    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err
        .to_string()
        .contains(TXCONTEXT_TOO_MANY_CONTINUING_OUTPUTS));
}
