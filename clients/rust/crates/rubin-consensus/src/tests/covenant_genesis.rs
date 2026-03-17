use super::*;

#[test]
fn validate_tx_covenants_genesis_p2pk_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    let mut cov = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    cov[0] = SUITE_ID_ML_DSA_87;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov,
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_p2pk_non_native_suite_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    let mut cov = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    cov[0] = 0x02; // non-native / unknown suite
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov,
    }];

    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn validate_tx_covenants_genesis_unassigned_0001_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: 0x0001,
        covenant_data: vec![0x00],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_anchor_nonzero_value() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_ANCHOR,
        covenant_data: vec![0x01],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_p2pk_zero_value_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    let mut cov = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    cov[0] = SUITE_ID_ML_DSA_87;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 0,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: cov,
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_p2pk_bad_length_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_P2PK,
        covenant_data: vec![SUITE_ID_ML_DSA_87; (MAX_P2PK_COVENANT_DATA - 1) as usize],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_anchor_zero_length_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 0,
        covenant_type: COV_TYPE_ANCHOR,
        covenant_data: vec![],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_anchor_valid() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 0,
        covenant_type: COV_TYPE_ANCHOR,
        covenant_data: vec![0x42],
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_vault_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: valid_vault_covenant_data_for_p2pk_output(),
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_vault_bad_threshold() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: encode_vault_covenant_data(
            [0x99u8; 32],
            3,
            &make_keys(2, 0x11),
            &make_keys(1, 0x51),
        ),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
}

#[test]
fn validate_tx_covenants_genesis_vault_unsorted_keys() {
    let mut keys = make_keys(2, 0x11);
    keys.swap(0, 1);
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: encode_vault_covenant_data([0x99u8; 32], 1, &keys, &make_keys(1, 0x51)),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultKeysNotCanonical);
}

#[test]
fn validate_tx_covenants_genesis_vault_unsorted_whitelist() {
    let keys = make_keys(1, 0x11);
    let mut whitelist = make_keys(2, 0x51);
    whitelist.swap(0, 1);
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_VAULT,
        covenant_data: encode_vault_covenant_data([0x99u8; 32], 1, &keys, &whitelist),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultWhitelistNotCanonical);
}

#[test]
fn validate_tx_covenants_genesis_multisig_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_MULTISIG,
        covenant_data: encode_multisig_covenant_data(2, &make_keys(2, 0x31)),
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_multisig_bad_threshold() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_MULTISIG,
        covenant_data: encode_multisig_covenant_data(3, &make_keys(2, 0x31)),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_multisig_unsorted_keys() {
    let mut keys = make_keys(2, 0x31);
    keys.swap(0, 1);
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_MULTISIG,
        covenant_data: encode_multisig_covenant_data(1, &keys),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_htlc_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_HTLC,
        covenant_data: encode_htlc_covenant_data(
            [0x42u8; 32],
            LOCK_MODE_HEIGHT,
            5,
            [0x11u8; 32],
            [0x22u8; 32],
        ),
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_htlc_zero_value_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 0,
        covenant_type: COV_TYPE_HTLC,
        covenant_data: encode_htlc_covenant_data(
            [0x42u8; 32],
            LOCK_MODE_HEIGHT,
            5,
            [0x11u8; 32],
            [0x22u8; 32],
        ),
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_ext_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    let mut cov = Vec::new();
    cov.extend_from_slice(&7u16.to_le_bytes());
    crate::compactsize::encode_compact_size(2, &mut cov);
    cov.extend_from_slice(&[0xaa, 0xbb]);
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_EXT,
        covenant_data: cov,
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_ext_zero_value_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    let mut cov = Vec::new();
    cov.extend_from_slice(&7u16.to_le_bytes());
    crate::compactsize::encode_compact_size(0, &mut cov);
    tx.outputs = vec![crate::tx::TxOutput {
        value: 0,
        covenant_type: COV_TYPE_EXT,
        covenant_data: cov,
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_stealth_ok() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    let cov = vec![0x55u8; MAX_STEALTH_COVENANT_DATA as usize];
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_STEALTH,
        covenant_data: cov,
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_stealth_zero_value_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 0,
        covenant_type: COV_TYPE_STEALTH,
        covenant_data: vec![0x55u8; MAX_STEALTH_COVENANT_DATA as usize],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_da_commit_requires_da_tx_kind() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.tx_kind = 0x00;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 0,
        covenant_type: COV_TYPE_DA_COMMIT,
        covenant_data: vec![0x33; 32],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_da_commit_valid_for_da_tx() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.tx_kind = 0x01;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 0,
        covenant_type: COV_TYPE_DA_COMMIT,
        covenant_data: vec![0x33; 32],
    }];
    validate_tx_covenants_genesis(&tx, 0).expect("ok");
}

#[test]
fn validate_tx_covenants_genesis_reserved_future_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: COV_TYPE_RESERVED_FUTURE,
        covenant_data: vec![0x00],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn validate_tx_covenants_genesis_unknown_type_rejected() {
    let mut tx = parse_tx(&minimal_tx_bytes()).expect("parse").0;
    tx.outputs = vec![crate::tx::TxOutput {
        value: 1,
        covenant_type: 0xffff,
        covenant_data: vec![0x00],
    }];
    let err = validate_tx_covenants_genesis(&tx, 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn witness_slots_unknown_covenant_rejected() {
    let err = crate::witness_slots(0x7777, &[]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}
