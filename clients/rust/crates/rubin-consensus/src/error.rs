use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    TxErrParse,
    TxErrWitnessOverflow,
    TxErrSigNoncanonical,
    TxErrSigAlgInvalid,
    TxErrSigInvalid,
    TxErrCovenantTypeInvalid,
    TxErrMissingUtxo,
    TxErrTimelockNotMet,

    BlockErrParse,
    BlockErrWeightExceeded,
    BlockErrAnchorBytesExceeded,
    BlockErrPowInvalid,
    BlockErrLinkageInvalid,
    BlockErrMerkleInvalid,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::TxErrParse => "TX_ERR_PARSE",
            ErrorCode::TxErrWitnessOverflow => "TX_ERR_WITNESS_OVERFLOW",
            ErrorCode::TxErrSigNoncanonical => "TX_ERR_SIG_NONCANONICAL",
            ErrorCode::TxErrSigAlgInvalid => "TX_ERR_SIG_ALG_INVALID",
            ErrorCode::TxErrSigInvalid => "TX_ERR_SIG_INVALID",
            ErrorCode::TxErrCovenantTypeInvalid => "TX_ERR_COVENANT_TYPE_INVALID",
            ErrorCode::TxErrMissingUtxo => "TX_ERR_MISSING_UTXO",
            ErrorCode::TxErrTimelockNotMet => "TX_ERR_TIMELOCK_NOT_MET",

            ErrorCode::BlockErrParse => "BLOCK_ERR_PARSE",
            ErrorCode::BlockErrWeightExceeded => "BLOCK_ERR_WEIGHT_EXCEEDED",
            ErrorCode::BlockErrAnchorBytesExceeded => "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED",
            ErrorCode::BlockErrPowInvalid => "BLOCK_ERR_POW_INVALID",
            ErrorCode::BlockErrLinkageInvalid => "BLOCK_ERR_LINKAGE_INVALID",
            ErrorCode::BlockErrMerkleInvalid => "BLOCK_ERR_MERKLE_INVALID",
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
