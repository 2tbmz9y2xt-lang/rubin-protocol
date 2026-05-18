#[test]
fn p2pk_covenant_data_for_pubkey_emits_canonical_shape_and_is_deterministic() {
    let pubkey = b"rubin-p2pk-shape";
    let covenant_data = p2pk_covenant_data_for_pubkey(pubkey);
    let repeated = p2pk_covenant_data_for_pubkey(pubkey);

    assert_eq!(covenant_data.len(), MAX_P2PK_COVENANT_DATA as usize);
    assert_eq!(covenant_data[0], SUITE_ID_ML_DSA_87);
    assert_eq!(covenant_data[1..33], sha3_256(pubkey));
    assert_eq!(covenant_data, repeated);
}

#[test]
fn marshal_tx_roundtrips_via_parse_tx() {
    let tx = test_tx();
    let bytes = marshal_tx(&tx).expect("marshal");
    let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, tx);
}

#[test]
fn marshal_tx_with_inputs_outputs_roundtrips() {
    let mut tx = test_tx();
    tx.tx_nonce = 42;
    tx.inputs[0].prev_txid[0..3].copy_from_slice(&[0x01, 0x02, 0x03]);
    tx.inputs[0].prev_vout = 7;
    tx.inputs[0].script_sig = vec![0xaa, 0xbb];
    tx.inputs[0].sequence = u32::MAX;
    tx.outputs = vec![
        TxOutput {
            value: 50_000,
            covenant_type: 0,
            covenant_data: Vec::new(),
        },
        TxOutput {
            value: 10_000,
            covenant_type: 1,
            covenant_data: vec![0xcc],
        },
    ];
    tx.locktime = 100;

    let bytes = marshal_tx(&tx).expect("marshal");
    let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.inputs.len(), 1);
    assert_eq!(parsed.inputs[0].prev_txid, tx.inputs[0].prev_txid);
    assert_eq!(parsed.outputs.len(), 2);
    assert_eq!(parsed.outputs[0].value, 50_000);
    assert_eq!(parsed.locktime, 100);
}

#[test]
fn marshal_tx_empty_da_payload_roundtrips() {
    let tx = Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x00,
        tx_nonce: 0,
        inputs: Vec::new(),
        outputs: Vec::new(),
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };

    let bytes = marshal_tx(&tx).expect("marshal");
    let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse");
    assert_eq!(consumed, bytes.len());
    assert!(parsed.da_payload.is_empty());
}

#[test]
fn marshal_tx_da_commit_roundtrips() {
    let tx = da_commit_tx();
    let bytes = marshal_tx(&tx).expect("marshal commit");
    let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse commit");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.da_commit_core, tx.da_commit_core);
    assert_eq!(parsed.da_payload, tx.da_payload);
}

#[test]
fn marshal_tx_da_chunk_roundtrips() {
    let tx = da_chunk_tx();
    let bytes = marshal_tx(&tx).expect("marshal chunk");
    let (parsed, _, _, consumed) = parse_tx(&bytes).expect("parse chunk");
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.da_chunk_core, tx.da_chunk_core);
    assert_eq!(parsed.da_payload, tx.da_payload);
}

#[test]
fn marshal_tx_da_kind_missing_core_errors() {
    let tx_commit = Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x01,
        tx_nonce: 0,
        inputs: Vec::new(),
        outputs: Vec::new(),
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: vec![0x01],
    };
    let err = marshal_tx(&tx_commit).expect_err("missing commit core must fail");
    assert_eq!(err.code, ErrorCode::TxErrParse);

    let tx_chunk = Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x02,
        tx_nonce: 0,
        inputs: Vec::new(),
        outputs: Vec::new(),
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: vec![0x01],
    };
    let err = marshal_tx(&tx_chunk).expect_err("missing chunk core must fail");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}
