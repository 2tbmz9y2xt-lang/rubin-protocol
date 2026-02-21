package consensus

import "fmt"

type ErrorCode string

const (
	TX_ERR_PARSE            ErrorCode = "TX_ERR_PARSE"
	TX_ERR_WITNESS_OVERFLOW ErrorCode = "TX_ERR_WITNESS_OVERFLOW"
	TX_ERR_SIG_NONCANONICAL ErrorCode = "TX_ERR_SIG_NONCANONICAL"
	TX_ERR_SIG_ALG_INVALID  ErrorCode = "TX_ERR_SIG_ALG_INVALID"
	TX_ERR_SIG_INVALID      ErrorCode = "TX_ERR_SIG_INVALID"

	TX_ERR_COVENANT_TYPE_INVALID ErrorCode = "TX_ERR_COVENANT_TYPE_INVALID"
	TX_ERR_MISSING_UTXO          ErrorCode = "TX_ERR_MISSING_UTXO"
	TX_ERR_TIMELOCK_NOT_MET      ErrorCode = "TX_ERR_TIMELOCK_NOT_MET"

	BLOCK_ERR_PARSE                 ErrorCode = "BLOCK_ERR_PARSE"
	BLOCK_ERR_WEIGHT_EXCEEDED       ErrorCode = "BLOCK_ERR_WEIGHT_EXCEEDED"
	BLOCK_ERR_ANCHOR_BYTES_EXCEEDED ErrorCode = "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED"
	BLOCK_ERR_POW_INVALID           ErrorCode = "BLOCK_ERR_POW_INVALID"
	BLOCK_ERR_LINKAGE_INVALID       ErrorCode = "BLOCK_ERR_LINKAGE_INVALID"
	BLOCK_ERR_MERKLE_INVALID        ErrorCode = "BLOCK_ERR_MERKLE_INVALID"
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
