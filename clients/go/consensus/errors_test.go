package consensus

import "testing"

func TestTxError_ErrorFormatting(t *testing.T) {
	var e *TxError
	if got := e.Error(); got != "<nil>" {
		t.Fatalf("nil receiver: %q", got)
	}

	e = &TxError{Code: TX_ERR_PARSE, Msg: ""}
	if got := e.Error(); got != "TX_ERR_PARSE" {
		t.Fatalf("empty msg: %q", got)
	}

	e = &TxError{Code: TX_ERR_PARSE, Msg: "bad"}
	if got := e.Error(); got != "TX_ERR_PARSE: bad" {
		t.Fatalf("with msg: %q", got)
	}
}

func TestTxerrReturnsTxError(t *testing.T) {
	err := txerr(TX_ERR_SIG_ALG_INVALID, "x")
	te, ok := err.(*TxError)
	if !ok {
		t.Fatalf("expected *TxError, got %T", err)
	}
	if te.Code != TX_ERR_SIG_ALG_INVALID || te.Msg != "x" {
		t.Fatalf("unexpected fields: %#v", te)
	}
}
