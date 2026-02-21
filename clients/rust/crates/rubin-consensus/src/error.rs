use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    TxErrParse,
    TxErrWitnessOverflow,
    TxErrSigNoncanonical,
    TxErrSigAlgInvalid,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::TxErrParse => "TX_ERR_PARSE",
            ErrorCode::TxErrWitnessOverflow => "TX_ERR_WITNESS_OVERFLOW",
            ErrorCode::TxErrSigNoncanonical => "TX_ERR_SIG_NONCANONICAL",
            ErrorCode::TxErrSigAlgInvalid => "TX_ERR_SIG_ALG_INVALID",
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
