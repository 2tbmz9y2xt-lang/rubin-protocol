use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    TxErrParse,
    TxErrWitnessOverflow,
    TxErrSigNoncanonical,
    TxErrSigAlgInvalid,
    TxErrSigInvalid,
    TxErrValueConservation,
    TxErrTxNonceInvalid,
    TxErrSequenceInvalid,
    TxErrNonceReplay,
    TxErrCovenantTypeInvalid,
    TxErrMissingUtxo,
    TxErrCoinbaseImmature,
    TxErrTimelockNotMet,

    BlockErrParse,
    BlockErrWeightExceeded,
    BlockErrAnchorBytesExceeded,
    BlockErrPowInvalid,
    BlockErrTargetInvalid,
    BlockErrLinkageInvalid,
    BlockErrMerkleInvalid,
    BlockErrWitnessCommitment,
    BlockErrCoinbaseInvalid,
    BlockErrSubsidyExceeded,
    BlockErrTimestampOld,
    BlockErrTimestampFuture,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::TxErrParse => "TX_ERR_PARSE",
            ErrorCode::TxErrWitnessOverflow => "TX_ERR_WITNESS_OVERFLOW",
            ErrorCode::TxErrSigNoncanonical => "TX_ERR_SIG_NONCANONICAL",
            ErrorCode::TxErrSigAlgInvalid => "TX_ERR_SIG_ALG_INVALID",
            ErrorCode::TxErrSigInvalid => "TX_ERR_SIG_INVALID",
            ErrorCode::TxErrValueConservation => "TX_ERR_VALUE_CONSERVATION",
            ErrorCode::TxErrTxNonceInvalid => "TX_ERR_TX_NONCE_INVALID",
            ErrorCode::TxErrSequenceInvalid => "TX_ERR_SEQUENCE_INVALID",
            ErrorCode::TxErrNonceReplay => "TX_ERR_NONCE_REPLAY",
            ErrorCode::TxErrCovenantTypeInvalid => "TX_ERR_COVENANT_TYPE_INVALID",
            ErrorCode::TxErrMissingUtxo => "TX_ERR_MISSING_UTXO",
            ErrorCode::TxErrCoinbaseImmature => "TX_ERR_COINBASE_IMMATURE",
            ErrorCode::TxErrTimelockNotMet => "TX_ERR_TIMELOCK_NOT_MET",

            ErrorCode::BlockErrParse => "BLOCK_ERR_PARSE",
            ErrorCode::BlockErrWeightExceeded => "BLOCK_ERR_WEIGHT_EXCEEDED",
            ErrorCode::BlockErrAnchorBytesExceeded => "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED",
            ErrorCode::BlockErrPowInvalid => "BLOCK_ERR_POW_INVALID",
            ErrorCode::BlockErrTargetInvalid => "BLOCK_ERR_TARGET_INVALID",
            ErrorCode::BlockErrLinkageInvalid => "BLOCK_ERR_LINKAGE_INVALID",
            ErrorCode::BlockErrMerkleInvalid => "BLOCK_ERR_MERKLE_INVALID",
            ErrorCode::BlockErrWitnessCommitment => "BLOCK_ERR_WITNESS_COMMITMENT",
            ErrorCode::BlockErrCoinbaseInvalid => "BLOCK_ERR_COINBASE_INVALID",
            ErrorCode::BlockErrSubsidyExceeded => "BLOCK_ERR_SUBSIDY_EXCEEDED",
            ErrorCode::BlockErrTimestampOld => "BLOCK_ERR_TIMESTAMP_OLD",
            ErrorCode::BlockErrTimestampFuture => "BLOCK_ERR_TIMESTAMP_FUTURE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxError {
    pub code: ErrorCode,
    pub msg: &'static str,
}

impl TxError {
    pub fn new(code: ErrorCode, msg: &'static str) -> Self {
        Self { code, msg }
    }
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.msg.is_empty() {
            write!(f, "{}", self.code.as_str())
        } else {
            write!(f, "{}: {}", self.code.as_str(), self.msg)
        }
    }
}

impl std::error::Error for TxError {}
