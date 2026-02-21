package consensus

import "fmt"

type ErrorCode string

const (
	TX_ERR_PARSE            ErrorCode = "TX_ERR_PARSE"
	TX_ERR_WITNESS_OVERFLOW ErrorCode = "TX_ERR_WITNESS_OVERFLOW"
	TX_ERR_SIG_NONCANONICAL ErrorCode = "TX_ERR_SIG_NONCANONICAL"
	TX_ERR_SIG_ALG_INVALID  ErrorCode = "TX_ERR_SIG_ALG_INVALID"
)

type TxError struct {
	Code ErrorCode
	Msg  string
}

func (e *TxError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Msg == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Msg)
}

func txerr(code ErrorCode, msg string) error {
	return &TxError{Code: code, Msg: msg}
}
