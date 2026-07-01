use super::*;
use crate::compactsize::encode_compact_size;
use crate::constants::{
    COV_TYPE_CORE_SIMPLICITY, COV_TYPE_P2PK, MAX_DA_CHUNK_COUNT, MAX_DA_MANIFEST_BYTES_PER_TX,
    MAX_TX_INPUTS, MAX_TX_OUTPUTS, SIGHASH_ALL, SIMPLICITY_MAX_GROUP_INPUTS,
};
use crate::error::ErrorCode;
use crate::tx::{DaChunkCore, DaCommitCore, Tx, TxInput, TxOutput};
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

fn core_out(value: u64, program_cmr: [u8; 32], state: &[u8]) -> TxOutput {
    TxOutput {
        value,
        covenant_type: COV_TYPE_CORE_SIMPLICITY,
        covenant_data: covenant(program_cmr, state),
    }
}

fn da_commit(chunk_count: u16, batch_sig: Vec<u8>) -> DaCommitCore {
    DaCommitCore {
        da_id: [0u8; 32],
        chunk_count,
        retl_domain_id: [0u8; 32],
        batch_number: 0,
        tx_data_root: [0u8; 32],
        state_root: [0u8; 32],
        withdrawals_root: [0u8; 32],
        batch_sig_suite: 0,
        batch_sig,
    }
}

fn chunk_core(da_id: [u8; 32], chunk_index: u16, chunk_hash: [u8; 32]) -> DaChunkCore {
    DaChunkCore {
        da_id,
        chunk_index,
        chunk_hash,
    }
}

fn ge(state: &[u8], value: u64) -> SimplicityTxContextGroupEntry {
    SimplicityTxContextGroupEntry {
        state: state.to_vec(),
        value,
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
    // tx_kind=0x02 with a valid da_chunk_core so the tx is well-formed in both
    // clients (RUB-500 core ignores DA; the DA view + validation is RUB-501).
    tx.tx_kind = 2;
    tx.da_chunk_core = Some(DaChunkCore {
        da_id: [0u8; 32],
        chunk_index: 0,
        chunk_hash: [0u8; 32],
    });
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

    // Same-CMR view fail-closed on a non-CORE_SIMPLICITY input (input 1 is P2PK).
    let e3 = ctx.same_cmr_view(1).expect_err("non-core same-cmr");
    assert_eq!(e3.code, ErrorCode::TxErrCovenantTypeInvalid);
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

#[test]
fn rejects_zero_value_core_simplicity_output() {
    // Mirrors Go: the output covenant is parsed too — a zero-value output fails closed.
    let cmr = [0xbau8; 32];
    let tx = tx_with(vec![input()], vec![core_out(0, cmr, &[])]);
    let resolved = vec![utxo(1, COV_TYPE_CORE_SIMPLICITY, covenant(cmr, &[]))];
    let err = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32]).expect_err("zero output");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert_eq!(err.msg, "CORE_SIMPLICITY value must be > 0");
}

#[test]
fn same_cmr_view_projection() {
    // Group both inputs AND outputs by program_cmr (symmetric B-1), ascending
    // order, foreign CMRs excluded, returned entries are fresh copies.
    let cmr_a = [0xa0u8; 32];
    let cmr_b = [0xb0u8; 32];
    let tx = tx_with(
        vec![input(), input(), input()],
        vec![core_out(44, cmr_a, &[0x04]), core_out(55, cmr_b, &[0x05])],
    );
    let resolved = vec![
        utxo(11, COV_TYPE_CORE_SIMPLICITY, covenant(cmr_a, &[0x01])),
        utxo(22, COV_TYPE_CORE_SIMPLICITY, covenant(cmr_b, &[0x02])),
        utxo(33, COV_TYPE_CORE_SIMPLICITY, covenant(cmr_a, &[0x03])),
    ];
    let ctx = build_simplicity_tx_context(&tx, &resolved, 7, [0u8; 32])
        .expect("build")
        .expect("context");

    let mut view_a = ctx.same_cmr_view(0).expect("view a");
    assert_eq!(view_a.program_cmr, cmr_a);
    assert_eq!(view_a.inputs, vec![ge(&[0x01], 11), ge(&[0x03], 33)]);
    assert_eq!(view_a.outputs, vec![ge(&[0x04], 44)]);

    // Projection isolation: mutating the returned view cannot alias the ctx.
    view_a.inputs[0].state[0] = 0xff;
    assert_eq!(
        ctx.same_cmr_view(0).expect("view a again").inputs[0].state,
        vec![0x01]
    );

    let view_b = ctx.same_cmr_view(1).expect("view b");
    assert_eq!(view_b.program_cmr, cmr_b);
    assert_eq!(view_b.inputs, vec![ge(&[0x02], 22)]);
    assert_eq!(view_b.outputs, vec![ge(&[0x05], 55)]);

    let err = ctx.same_cmr_view(3).expect_err("out of range");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn same_cmr_input_cap() {
    let cmr = [0xc0u8; 32];
    let n = SIMPLICITY_MAX_GROUP_INPUTS + 1; // 9
    let mut resolved: Vec<UtxoEntry> = (0..n)
        .map(|_| utxo(1, COV_TYPE_CORE_SIMPLICITY, covenant(cmr, &[])))
        .collect();
    let tx = tx_with(vec![input(); n], vec![]);

    // Exactly SIMPLICITY_MAX_GROUP_INPUTS (8) same-CMR inputs sit at the cap -> pass.
    let tx_exact = tx_with(vec![input(); SIMPLICITY_MAX_GROUP_INPUTS], vec![]);
    build_simplicity_tx_context(
        &tx_exact,
        &resolved[..SIMPLICITY_MAX_GROUP_INPUTS],
        1,
        [0u8; 32],
    )
    .expect("8 same-cmr inputs pass the cap");

    // 9 inputs but the 9th splits into its own CMR group -> pass.
    resolved[SIMPLICITY_MAX_GROUP_INPUTS].covenant_data = covenant([0xc1u8; 32], &[]);
    build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32]).expect("9 split-cmr inputs pass");

    // 9 inputs all in one CMR group -> fail closed.
    resolved[SIMPLICITY_MAX_GROUP_INPUTS].covenant_data = covenant(cmr, &[]);
    let err = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32]).expect_err("9 same-cmr");
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert_eq!(
        err.msg,
        "CORE_SIMPLICITY same-cmr input group exceeds limit"
    );
}

#[test]
fn da_view_kinds_and_rejects() {
    let da_id = [0x01u8; 32];
    let resolved = vec![utxo(
        1,
        COV_TYPE_CORE_SIMPLICITY,
        covenant([0xd0u8; 32], &[]),
    )];
    let da_view_of = |tx_kind: u8,
                      commit: Option<DaCommitCore>,
                      chunk: Option<DaChunkCore>|
     -> Result<SimplicityTxContextDaView, TxError> {
        let mut tx = tx_with(vec![input()], vec![]);
        tx.tx_kind = tx_kind;
        tx.da_commit_core = commit;
        tx.da_chunk_core = chunk;
        Ok(build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32])?
            .expect("context")
            .da_view)
    };

    // commit (0x01): copies commit fields, excludes batch_sig, ignores stale chunk.
    let mut commit_core = da_commit(2, vec![0xaa, 0xbb]);
    commit_core.da_id = da_id;
    commit_core.batch_number = 9;
    let commit = da_view_of(
        0x01,
        Some(commit_core),
        Some(chunk_core(da_id, 7, [0u8; 32])),
    )
    .expect("commit");
    assert_eq!(
        commit,
        SimplicityTxContextDaView {
            kind: SimplicityTxContextDaViewKind::Commit,
            commit: SimplicityTxContextDaCommitView {
                da_id,
                chunk_count: 2,
                batch_number: 9,
                ..Default::default()
            },
            chunk: SimplicityTxContextDaChunkView::default(),
        }
    );

    // absent (0x00) ignores stale cores; chunk (0x02) ignores stale commit.
    let absent = da_view_of(
        0x00,
        Some(da_commit(0, vec![])),
        Some(chunk_core(da_id, 1, [0u8; 32])),
    )
    .expect("absent");
    assert_eq!(absent, SimplicityTxContextDaView::default());

    let chunk_hash = [0x03u8; 32];
    let chunk = da_view_of(
        0x02,
        Some(da_commit(0, vec![])),
        Some(chunk_core(da_id, 4, chunk_hash)),
    )
    .expect("chunk");
    assert_eq!(
        chunk,
        SimplicityTxContextDaView {
            kind: SimplicityTxContextDaViewKind::Chunk,
            commit: SimplicityTxContextDaCommitView::default(),
            chunk: SimplicityTxContextDaChunkView {
                da_id,
                chunk_index: 4,
                chunk_hash
            },
        }
    );

    // Every malformed / unsupported DA shape fails closed with TX_ERR_PARSE.
    let big_sig = vec![0u8; usize::try_from(MAX_DA_MANIFEST_BYTES_PER_TX + 1).expect("fits usize")];
    let over_chunks = u16::try_from(MAX_DA_CHUNK_COUNT + 1).expect("fits u16");
    let over_index = u16::try_from(MAX_DA_CHUNK_COUNT).expect("fits u16");
    #[rustfmt::skip]
    let rejects: [(&str, u8, Option<DaCommitCore>, Option<DaChunkCore>); 7] = [
        ("missing commit core", 0x01, None, None),
        ("missing chunk core", 0x02, None, None),
        ("unsupported tx kind", 0x03, None, None),
        ("zero commit chunk count", 0x01, Some(da_commit(0, vec![])), None),
        ("too many commit chunks", 0x01, Some(da_commit(over_chunks, vec![])), None),
        ("oversized batch sig", 0x01, Some(da_commit(1, big_sig)), None),
        ("chunk index out of range", 0x02, None, Some(chunk_core(da_id, over_index, [0u8; 32]))),
    ];
    for (name, kind, commit, chunk) in rejects {
        let code = da_view_of(kind, commit, chunk).expect_err(name).code;
        assert_eq!(code, ErrorCode::TxErrParse, "{name}");
    }
}

fn p2pk_out(value: u64, covenant_data: Vec<u8>) -> TxOutput {
    TxOutput {
        value,
        covenant_type: COV_TYPE_P2PK,
        covenant_data,
    }
}

fn access_cost(descriptor: &[u8]) -> u64 {
    simplicity::DESCRIPTOR_HASH_BASE_COST
        + descriptor.len() as u64 * simplicity::DESCRIPTOR_HASH_BYTE_COST
}

fn descriptor_source(
    covenant_type: u16,
    covenant_data: Vec<u8>,
) -> SimplicityTxContextDescriptorSource {
    SimplicityTxContextDescriptorSource {
        covenant_type,
        covenant_data,
    }
}

#[test]
fn descriptor_hash_accessors_accumulate_cost() {
    let cmr = [0xdau8; 32];
    let mut input_data = vec![0x01, 0xaa, 0xbb];
    let mut output_data = vec![0x01, 0xcc, 0xdd];
    let tx = tx_with(
        vec![input(), input()],
        vec![p2pk_out(3, output_data.clone())],
    );
    let resolved = vec![
        utxo(1, COV_TYPE_CORE_SIMPLICITY, covenant(cmr, &[])),
        utxo(2, COV_TYPE_P2PK, input_data.clone()),
    ];
    let ctx = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32])
        .expect("build")
        .expect("context");
    // Mutating the sources after build must not affect the copied descriptors.
    input_data[0] = 0xff;
    output_data[0] = 0xff;

    let input_desc = output_descriptor_bytes(COV_TYPE_P2PK, &[0x01, 0xaa, 0xbb]);
    let input_cost = access_cost(&input_desc);
    let mut meter = SimplicityTxContextMeter::default();
    for i in 1..=2u64 {
        let got = ctx
            .input_descriptor_hash(1, &mut meter)
            .expect("input hash");
        assert!(got.present);
        assert_eq!(got.hash, sha3_256(&input_desc));
        assert_eq!(meter.cost(), i * input_cost);
    }

    let output_desc = output_descriptor_bytes(COV_TYPE_P2PK, &[0x01, 0xcc, 0xdd]);
    let got = ctx
        .output_descriptor_hash(0, &mut meter)
        .expect("output hash");
    assert!(got.present);
    assert_eq!(got.hash, sha3_256(&output_desc));
    assert_eq!(meter.cost(), 2 * input_cost + access_cost(&output_desc));
}

#[test]
fn descriptor_hash_miss_and_budget_cross() {
    let cmr = [0xdbu8; 32];
    let tx = tx_with(vec![input()], vec![]);
    let resolved = vec![utxo(1, COV_TYPE_CORE_SIMPLICITY, covenant(cmr, &[]))];
    let ctx = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32])
        .expect("build")
        .expect("context");

    // Out-of-range index charges only the miss cost and reports not-present.
    let mut miss = SimplicityTxContextMeter::default();
    let got = ctx.input_descriptor_hash(1, &mut miss).expect("miss");
    assert!(!got.present);
    assert_eq!(got.hash, [0u8; 32]);
    assert_eq!(miss.cost(), simplicity::INTRINSIC_MISS_COST);

    // A meter primed one unit below the access cost saturates to MAX on charge.
    let cost = access_cost(&output_descriptor_bytes(
        COV_TYPE_CORE_SIMPLICITY,
        &covenant(cmr, &[]),
    ));
    let mut over = SimplicityTxContextMeter {
        cost: simplicity::MAX_EXEC_COST - cost + 1,
    };
    let err = ctx.input_descriptor_hash(0, &mut over).expect_err("budget");
    assert_eq!(err.code, simplicity::ErrorCode::BudgetExceeded);
    assert_eq!(over.cost(), simplicity::MAX_EXEC_COST);
}

#[test]
fn descriptor_hash_error_branches() {
    let cmr = [0xdcu8; 32];
    let tx = tx_with(vec![input()], vec![]);
    let resolved = vec![utxo(1, COV_TYPE_CORE_SIMPLICITY, covenant(cmr, &[]))];
    let ctx = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32])
        .expect("build")
        .expect("context");

    // A miss on an already-saturated meter still fails closed.
    let mut miss_over = SimplicityTxContextMeter {
        cost: simplicity::MAX_EXEC_COST,
    };
    let err = ctx
        .input_descriptor_hash(1, &mut miss_over)
        .expect_err("miss over budget");
    assert_eq!(err.code, simplicity::ErrorCode::BudgetExceeded);
    assert_eq!(miss_over.cost(), simplicity::MAX_EXEC_COST);

    // A single descriptor whose access cost alone exceeds the budget fails closed.
    let oversize = [descriptor_source(
        COV_TYPE_P2PK,
        vec![0u8; usize::try_from(simplicity::MAX_EXEC_COST).expect("fits usize")],
    )];
    let mut meter = SimplicityTxContextMeter::default();
    let err = descriptor_hash(&oversize, 0, &mut meter).expect_err("oversize");
    assert_eq!(err.code, simplicity::ErrorCode::BudgetExceeded);
    assert_eq!(meter.cost(), simplicity::MAX_EXEC_COST);
}

#[test]
fn descriptor_hash_equals_lock_id() {
    // The descriptor_hash intrinsic returns the covenant lock_id: sha3-256 of the
    // output-descriptor bytes — the same value utxo_basic derives for owner auth.
    let cmr = [0xd0u8; 32];
    let owner = vec![0x01u8; 33];
    let tx = tx_with(vec![input()], vec![p2pk_out(5, owner.clone())]);
    let resolved = vec![utxo(1, COV_TYPE_CORE_SIMPLICITY, covenant(cmr, &[]))];
    let ctx = build_simplicity_tx_context(&tx, &resolved, 1, [0u8; 32])
        .expect("build")
        .expect("context");

    let mut meter = SimplicityTxContextMeter::default();
    let got = ctx.output_descriptor_hash(0, &mut meter).expect("hash");
    assert!(got.present);
    assert_eq!(
        got.hash,
        sha3_256(&output_descriptor_bytes(COV_TYPE_P2PK, &owner))
    );
}
