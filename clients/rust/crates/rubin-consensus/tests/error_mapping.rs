use rubin_consensus::{ErrorCode, TxError};

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
