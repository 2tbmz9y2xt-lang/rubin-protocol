use rubin_consensus::{ErrorCode, TxError};

// --- ErrorCode derive coverage ---

#[test]
fn error_code_clone() {
    let a = ErrorCode::TxErrParse;
    let b = a;
    #[allow(clippy::clone_on_copy)]
    let c = a.clone(); // intentional: exercises Clone impl on Copy type
    assert_eq!(b, c);
}

#[test]
fn error_code_copy_semantics() {
    let a = ErrorCode::BlockErrPowInvalid;
    let b = a; // Copy
    assert_eq!(a, b); // a still usable after move — Copy trait
}

#[test]
fn error_code_eq_same_variant() {
    assert_eq!(ErrorCode::TxErrSigInvalid, ErrorCode::TxErrSigInvalid);
}

#[test]
fn error_code_ne_different_variants() {
    assert_ne!(ErrorCode::TxErrParse, ErrorCode::BlockErrParse);
    assert_ne!(ErrorCode::TxErrSigInvalid, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn error_code_debug_format() {
    let dbg = format!("{:?}", ErrorCode::TxErrVaultMalformed);
    assert_eq!(dbg, "TxErrVaultMalformed");
}

// --- TxError constructor ---

#[test]
fn tx_error_new_fields() {
    let e = TxError::new(ErrorCode::TxErrParse, "details");
    assert_eq!(e.code, ErrorCode::TxErrParse);
    assert_eq!(e.msg, "details");
}

#[test]
fn tx_error_new_empty_msg() {
    let e = TxError::new(ErrorCode::BlockErrPowInvalid, "");
    assert_eq!(e.code, ErrorCode::BlockErrPowInvalid);
    assert!(e.msg.is_empty());
}

// --- TxError derive coverage ---

#[test]
fn tx_error_clone() {
    let a = TxError::new(ErrorCode::TxErrSigInvalid, "bad sig");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn tx_error_eq_same() {
    let a = TxError::new(ErrorCode::TxErrParse, "x");
    let b = TxError::new(ErrorCode::TxErrParse, "x");
    assert_eq!(a, b);
}

#[test]
fn tx_error_ne_different_code() {
    let a = TxError::new(ErrorCode::TxErrParse, "x");
    let b = TxError::new(ErrorCode::TxErrSigInvalid, "x");
    assert_ne!(a, b);
}

#[test]
fn tx_error_ne_different_msg() {
    let a = TxError::new(ErrorCode::TxErrParse, "x");
    let b = TxError::new(ErrorCode::TxErrParse, "y");
    assert_ne!(a, b);
}

#[test]
fn tx_error_debug_format() {
    let e = TxError::new(ErrorCode::TxErrParse, "oops");
    let dbg = format!("{:?}", e);
    assert!(dbg.contains("TxErrParse"));
    assert!(dbg.contains("oops"));
}

// --- std::error::Error trait ---

#[test]
fn tx_error_is_std_error() {
    let e = TxError::new(ErrorCode::TxErrParse, "test");
    let _: &dyn std::error::Error = &e; // must compile
                                        // source() returns None (no inner error)
    assert!(std::error::Error::source(&e).is_none());
}

// --- Display ---

#[test]
fn tx_error_display_empty_msg() {
    let e = TxError::new(ErrorCode::BlockErrMerkleInvalid, "");
    assert_eq!(e.to_string(), "BLOCK_ERR_MERKLE_INVALID");
}

#[test]
fn tx_error_display_with_msg() {
    let e = TxError::new(ErrorCode::BlockErrMerkleInvalid, "root mismatch");
    assert_eq!(e.to_string(), "BLOCK_ERR_MERKLE_INVALID: root mismatch");
}

#[test]
fn tx_error_display_all_tx_codes_nonempty() {
    // Verify every Tx* code produces non-empty Display output
    let tx_codes = [
        ErrorCode::TxErrParse,
        ErrorCode::TxErrWitnessOverflow,
        ErrorCode::TxErrSigNoncanonical,
        ErrorCode::TxErrSigAlgInvalid,
        ErrorCode::TxErrSigInvalid,
        ErrorCode::TxErrSighashTypeInvalid,
        ErrorCode::TxErrTimelockNotMet,
        ErrorCode::TxErrValueConservation,
        ErrorCode::TxErrTxNonceInvalid,
        ErrorCode::TxErrSequenceInvalid,
        ErrorCode::TxErrNonceReplay,
        ErrorCode::TxErrCovenantTypeInvalid,
        ErrorCode::TxErrVaultMalformed,
        ErrorCode::TxErrVaultParamsInvalid,
        ErrorCode::TxErrVaultKeysNotCanonical,
        ErrorCode::TxErrVaultWhitelistNotCanonical,
        ErrorCode::TxErrVaultOwnerDestinationForbidden,
        ErrorCode::TxErrVaultOwnerAuthRequired,
        ErrorCode::TxErrVaultFeeSponsorForbidden,
        ErrorCode::TxErrVaultMultiInputForbidden,
        ErrorCode::TxErrVaultOutputNotWhitelisted,
        ErrorCode::TxErrMissingUtxo,
        ErrorCode::TxErrCoinbaseImmature,
    ];
    for code in tx_codes {
        let e = TxError::new(code, "");
        let s = e.to_string();
        assert!(!s.is_empty(), "Display empty for {:?}", code);
        assert!(s.starts_with("TX_ERR_"), "bad prefix for {:?}: {}", code, s);
    }
}

#[test]
fn tx_error_display_all_block_codes_nonempty() {
    let block_codes = [
        ErrorCode::BlockErrParse,
        ErrorCode::BlockErrWeightExceeded,
        ErrorCode::BlockErrAnchorBytesExceeded,
        ErrorCode::BlockErrPowInvalid,
        ErrorCode::BlockErrTargetInvalid,
        ErrorCode::BlockErrLinkageInvalid,
        ErrorCode::BlockErrMerkleInvalid,
        ErrorCode::BlockErrWitnessCommitment,
        ErrorCode::BlockErrCoinbaseInvalid,
        ErrorCode::BlockErrSubsidyExceeded,
        ErrorCode::BlockErrTimestampOld,
        ErrorCode::BlockErrTimestampFuture,
        ErrorCode::BlockErrDaIncomplete,
        ErrorCode::BlockErrDaChunkHashInvalid,
        ErrorCode::BlockErrDaSetInvalid,
        ErrorCode::BlockErrDaPayloadCommitInvalid,
        ErrorCode::BlockErrDaBatchExceeded,
    ];
    for code in block_codes {
        let e = TxError::new(code, "");
        let s = e.to_string();
        assert!(!s.is_empty(), "Display empty for {:?}", code);
        assert!(
            s.starts_with("BLOCK_ERR_"),
            "bad prefix for {:?}: {}",
            code,
            s
        );
    }
}

// --- as_str exhaustive ---

#[test]
fn error_code_as_str_covers_all_variants() {
    // Intentionally list every variant: this keeps ErrorCode::as_str() coverage high and
    // guards against accidental renames/typos.
    let cases: &[(ErrorCode, &str)] = &[
        (ErrorCode::TxErrParse, "TX_ERR_PARSE"),
        (ErrorCode::TxErrWitnessOverflow, "TX_ERR_WITNESS_OVERFLOW"),
        (ErrorCode::TxErrSigNoncanonical, "TX_ERR_SIG_NONCANONICAL"),
        (ErrorCode::TxErrSigAlgInvalid, "TX_ERR_SIG_ALG_INVALID"),
        (ErrorCode::TxErrSigInvalid, "TX_ERR_SIG_INVALID"),
        (
            ErrorCode::TxErrSighashTypeInvalid,
            "TX_ERR_SIGHASH_TYPE_INVALID",
        ),
        (ErrorCode::TxErrTimelockNotMet, "TX_ERR_TIMELOCK_NOT_MET"),
        (
            ErrorCode::TxErrValueConservation,
            "TX_ERR_VALUE_CONSERVATION",
        ),
        (ErrorCode::TxErrTxNonceInvalid, "TX_ERR_TX_NONCE_INVALID"),
        (ErrorCode::TxErrSequenceInvalid, "TX_ERR_SEQUENCE_INVALID"),
        (ErrorCode::TxErrNonceReplay, "TX_ERR_NONCE_REPLAY"),
        (
            ErrorCode::TxErrCovenantTypeInvalid,
            "TX_ERR_COVENANT_TYPE_INVALID",
        ),
        (ErrorCode::TxErrVaultMalformed, "TX_ERR_VAULT_MALFORMED"),
        (
            ErrorCode::TxErrVaultParamsInvalid,
            "TX_ERR_VAULT_PARAMS_INVALID",
        ),
        (
            ErrorCode::TxErrVaultKeysNotCanonical,
            "TX_ERR_VAULT_KEYS_NOT_CANONICAL",
        ),
        (
            ErrorCode::TxErrVaultWhitelistNotCanonical,
            "TX_ERR_VAULT_WHITELIST_NOT_CANONICAL",
        ),
        (
            ErrorCode::TxErrVaultOwnerDestinationForbidden,
            "TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN",
        ),
        (
            ErrorCode::TxErrVaultOwnerAuthRequired,
            "TX_ERR_VAULT_OWNER_AUTH_REQUIRED",
        ),
        (
            ErrorCode::TxErrVaultFeeSponsorForbidden,
            "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN",
        ),
        (
            ErrorCode::TxErrVaultMultiInputForbidden,
            "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN",
        ),
        (
            ErrorCode::TxErrVaultOutputNotWhitelisted,
            "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED",
        ),
        (ErrorCode::TxErrMissingUtxo, "TX_ERR_MISSING_UTXO"),
        (ErrorCode::TxErrCoinbaseImmature, "TX_ERR_COINBASE_IMMATURE"),
        (ErrorCode::BlockErrParse, "BLOCK_ERR_PARSE"),
        (
            ErrorCode::BlockErrWeightExceeded,
            "BLOCK_ERR_WEIGHT_EXCEEDED",
        ),
        (
            ErrorCode::BlockErrAnchorBytesExceeded,
            "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED",
        ),
        (ErrorCode::BlockErrPowInvalid, "BLOCK_ERR_POW_INVALID"),
        (ErrorCode::BlockErrTargetInvalid, "BLOCK_ERR_TARGET_INVALID"),
        (
            ErrorCode::BlockErrLinkageInvalid,
            "BLOCK_ERR_LINKAGE_INVALID",
        ),
        (ErrorCode::BlockErrMerkleInvalid, "BLOCK_ERR_MERKLE_INVALID"),
        (
            ErrorCode::BlockErrWitnessCommitment,
            "BLOCK_ERR_WITNESS_COMMITMENT",
        ),
        (
            ErrorCode::BlockErrCoinbaseInvalid,
            "BLOCK_ERR_COINBASE_INVALID",
        ),
        (
            ErrorCode::BlockErrSubsidyExceeded,
            "BLOCK_ERR_SUBSIDY_EXCEEDED",
        ),
        (ErrorCode::BlockErrTimestampOld, "BLOCK_ERR_TIMESTAMP_OLD"),
        (
            ErrorCode::BlockErrTimestampFuture,
            "BLOCK_ERR_TIMESTAMP_FUTURE",
        ),
        (ErrorCode::BlockErrDaIncomplete, "BLOCK_ERR_DA_INCOMPLETE"),
        (
            ErrorCode::BlockErrDaChunkHashInvalid,
            "BLOCK_ERR_DA_CHUNK_HASH_INVALID",
        ),
        (ErrorCode::BlockErrDaSetInvalid, "BLOCK_ERR_DA_SET_INVALID"),
        (
            ErrorCode::BlockErrDaPayloadCommitInvalid,
            "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID",
        ),
        (
            ErrorCode::BlockErrDaBatchExceeded,
            "BLOCK_ERR_DA_BATCH_EXCEEDED",
        ),
    ];

    for (code, want) in cases {
        assert_eq!(code.as_str(), *want);
    }
}

#[test]
fn tx_error_display() {
    let e = TxError::new(ErrorCode::TxErrParse, "");
    assert_eq!(e.to_string(), "TX_ERR_PARSE");
    let e2 = TxError::new(ErrorCode::TxErrParse, "bad");
    assert_eq!(e2.to_string(), "TX_ERR_PARSE: bad");
}
